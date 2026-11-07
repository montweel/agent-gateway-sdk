#!/usr/bin/env node
/**
 * mont-gateway / agent-gateway-sdk CLI: the no-code standalone reverse proxy.
 *
 *   npx agent-gateway-sdk start --target https://api.mystore.com
 *
 * Two listeners:
 *   proxy  (default 127.0.0.1:8080)  /api/*                 guarded and forwarded to the target
 *                                    /_mont/approvals/*     signed phone Approve / Reject pages
 *                                    /.well-known/agent.json
 *                                    anything else          404 (never forwarded unguarded)
 *   admin  (default 127.0.0.1:3000)  /agent-admin/          dashboard incl. the No-Code Setup tab
 *                                    /api/agent-admin/*     admin API
 *
 * Port precedence for the proxy: --port, then PORT, then the port saved in the Setup tab, then 8080.
 */
import path from "path";
import fs from "fs";
import { parseArgs } from "util";
import type { NextFunction, Request, Response } from "express";
import type { Server } from "http";
import { createAgentGateway, readPersistedListenPort } from "./gateway";
import { createConfigStore } from "./core/config";
import { parseTargetUrl, sendCaughtError, sendError } from "./core/utils";
import { createBaseApp, installShutdown, listen, mountAdmin } from "./host";
import { DEFAULT_APPROVAL_WAIT_MS, createMcpHttpProxy, startMcpStdioProxy } from "./mcpProxy";

const DEFAULT_PROXY_PORT = 8080;
const DEFAULT_ADMIN_PORT = 3000;

function packageVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "package.json"), "utf8")) as { version?: string };
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

function usage(): string {
  return `Mont Agent Gateway ${packageVersion()}

Usage:
  agent-gateway-sdk start [options]     run the standalone gateway proxy + admin console
  agent-gateway-sdk mcp-http --upstream <url> [options]
                                        guard an MCP server over Streamable HTTP
  agent-gateway-sdk mcp-stdio [options] -- <command> [args...]
                                        guard a local stdio MCP server (use as the command in your MCP client)
  agent-gateway-sdk help                show this help
  agent-gateway-sdk --version

Options for mcp-http:
  --upstream <url>     the real MCP endpoint, e.g. http://127.0.0.1:9000/mcp
  --port <n>           proxy port (default 8090); clients connect to http://<host>:<port><path>
  --host <addr>        bind address (default 127.0.0.1)
  --path <p>           endpoint path (default /mcp)
  --wait-seconds <n>   how long a tool call needing approval is held (default 300)
  --admin-port, --admin-host, --data-dir   as for start

Options for mcp-stdio:
  --wait-seconds <n>   as above
  --admin-port <n>     admin console port (default 3000; skipped if busy, e.g. a second session)
  --no-admin           do not start the admin console
  --data-dir <dir>     as for start (share it between sessions to share rules and approvals)
  MONT_AGENT_KEY       optional agent key identifying this client
  Tool rules use the MCP method: "MCP /api/mcp/tools/<tool name>" (wildcards allowed).

Options for start:
  --target <url>       upstream API to protect (saved to config.json), e.g. https://api.mystore.com
  --port <n>           proxy port (default: PORT env, then the Setup tab value, then ${DEFAULT_PROXY_PORT})
  --host <addr>        proxy bind address (default: HOST env or 127.0.0.1; use 0.0.0.0 to expose it)
  --admin-port <n>     admin console port (default: ADMIN_PORT env or ${DEFAULT_ADMIN_PORT})
  --admin-host <addr>  admin console bind address (default: ADMIN_HOST env or 127.0.0.1)
  --data-dir <dir>     folder for rules.json, config.json and logs.db (default: current folder)

Agents call the proxy at http://<host>:<port>/api/... and the request is forwarded to
<target>/api/... only if your rules allow it. Configure everything else in the browser at
http://127.0.0.1:${DEFAULT_ADMIN_PORT}/agent-admin/ (Gateway Setup tab).`;
}

function parsePort(value: string | undefined, flag: string): number | undefined {
  if (value === undefined || value === "") return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`${flag} must be a port number from 1 to 65535.`);
  return n;
}

async function start(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      target: { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      "admin-port": { type: "string" },
      "admin-host": { type: "string" },
      "data-dir": { type: "string" },
    },
    strict: true,
  });

  const dataDir = path.resolve(values["data-dir"] ?? process.cwd());
  fs.mkdirSync(dataDir, { recursive: true });
  const rulesPath = path.join(dataDir, "rules.json");
  const configPath = path.join(dataDir, "config.json");
  const dbPath = path.join(dataDir, "logs.db");

  const savedPort = fs.existsSync(dbPath) ? await readPersistedListenPort(dbPath) : null;
  const proxyPort = parsePort(values.port, "--port") ?? parsePort(process.env.PORT, "PORT") ?? savedPort ?? DEFAULT_PROXY_PORT;
  const proxyHost = values.host ?? process.env.HOST ?? "127.0.0.1";
  const adminPort = parsePort(values["admin-port"], "--admin-port") ?? parsePort(process.env.ADMIN_PORT, "ADMIN_PORT") ?? DEFAULT_ADMIN_PORT;
  const adminHost = values["admin-host"] ?? process.env.ADMIN_HOST ?? "127.0.0.1";
  if (adminPort === proxyPort) throw new Error(`The admin port and the proxy port are both ${proxyPort}. Pick different ports.`);

  if (values.target !== undefined) {
    const parsed = parseTargetUrl(values.target, proxyPort);
    if (!parsed.ok) throw new Error(`--target: ${parsed.message}`);
    const store = createConfigStore(configPath, {});
    store.save({ ...store.load(), targetUrl: parsed.url });
    console.log(`Upstream target set to ${parsed.url}`);
  }

  const gateway = createAgentGateway({ port: proxyPort, rulesPath, configPath, dbPath, adminPort, adminHost });
  await gateway.ready;

  // ---- Public proxy listener ----
  const proxy = createBaseApp();
  proxy.use(gateway.discoveryRouter);
  proxy.use(gateway.approvalCallbackRouter);
  proxy.use("/api", gateway.agentGateway);
  // Reached only when a request was ALLOWED but no upstream is configured: refuse, never pretend.
  proxy.use("/api", (_req: Request, res: Response) => {
    sendError(res, 503, "Service Unavailable", "No upstream target is configured. Set one in the admin console (Gateway Setup tab).");
  });
  proxy.use((_req: Request, res: Response) => {
    sendError(res, 404, "Not Found", "Only /api/* is served by this gateway.");
  });
  proxy.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => sendCaughtError(res, err));

  // ---- Admin listener ----
  const admin = createBaseApp();
  mountAdmin(admin, gateway, process.env.NODE_ENV === "production");
  admin.get("/", (_req: Request, res: Response) => res.redirect("/agent-admin/"));
  admin.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => sendCaughtError(res, err));

  const servers: Server[] = [
    await listen(proxy, proxyPort, proxyHost, "Mont gateway proxy"),
    await listen(admin, adminPort, adminHost, "Mont admin console"),
  ];

  console.log("");
  console.log(`  Agents call:     http://${proxyHost}:${proxyPort}/api/...`);
  console.log(`  Admin console:   http://${adminHost}:${adminPort}/agent-admin/`);
  console.log(`  Data folder:     ${dataDir}`);
  console.log("  By using this SDK you agree to TERMS.md (see https://montweel.com).");
  console.log("");

  installShutdown(servers, gateway);
}

function dataPaths(dir: string | undefined): { dataDir: string; rulesPath: string; configPath: string; dbPath: string } {
  const dataDir = path.resolve(dir ?? process.cwd());
  fs.mkdirSync(dataDir, { recursive: true });
  return { dataDir, rulesPath: path.join(dataDir, "rules.json"), configPath: path.join(dataDir, "config.json"), dbPath: path.join(dataDir, "logs.db") };
}

function waitMs(value: string | undefined): number {
  if (value === undefined) return DEFAULT_APPROVAL_WAIT_MS;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 5 || n > 24 * 3600) throw new Error("--wait-seconds must be between 5 and 86400.");
  return Math.round(n * 1000);
}

async function mcpHttp(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      upstream: { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      path: { type: "string" },
      "wait-seconds": { type: "string" },
      "admin-port": { type: "string" },
      "admin-host": { type: "string" },
      "data-dir": { type: "string" },
    },
    strict: true,
  });
  if (!values.upstream) throw new Error("mcp-http needs --upstream <url> (the real MCP server endpoint).");
  const upstream = new URL(values.upstream);
  if (upstream.protocol !== "http:" && upstream.protocol !== "https:") throw new Error("--upstream must be an http(s) URL.");
  const port = parsePort(values.port, "--port") ?? 8090;
  const host = values.host ?? "127.0.0.1";
  const adminPort = parsePort(values["admin-port"], "--admin-port") ?? parsePort(process.env.ADMIN_PORT, "ADMIN_PORT") ?? DEFAULT_ADMIN_PORT;
  const adminHost = values["admin-host"] ?? process.env.ADMIN_HOST ?? "127.0.0.1";
  if (adminPort === port) throw new Error(`The admin port and the MCP proxy port are both ${port}.`);
  const mountPath = values.path ?? "/mcp";
  if (!mountPath.startsWith("/")) throw new Error("--path must start with /.");

  const { dataDir, rulesPath, configPath, dbPath } = dataPaths(values["data-dir"]);
  const gateway = createAgentGateway({ port, rulesPath, configPath, dbPath, adminPort, adminHost });
  await gateway.ready;

  const app = createBaseApp();
  app.use(gateway.approvalCallbackRouter);
  app.use(mountPath, createMcpHttpProxy(gateway, { upstreamUrl: upstream.toString(), approvalWaitMs: waitMs(values["wait-seconds"]) }));
  app.use((_req: Request, res: Response) => sendError(res, 404, "Not Found", `The MCP endpoint is ${mountPath}.`));

  const admin = createBaseApp();
  mountAdmin(admin, gateway, process.env.NODE_ENV === "production");
  admin.get("/", (_req: Request, res: Response) => res.redirect("/agent-admin/"));

  const servers: Server[] = [await listen(app, port, host, "Mont MCP proxy"), await listen(admin, adminPort, adminHost, "Mont admin console")];
  console.log("");
  console.log(`  MCP clients connect to: http://${host}:${port}${mountPath}`);
  console.log(`  Forwarding to:          ${upstream.toString()}`);
  console.log(`  Admin console:          http://${adminHost}:${adminPort}/agent-admin/`);
  console.log(`  Data folder:            ${dataDir}`);
  console.log('  Allow tools with rules like "MCP /api/mcp/tools/search_orders" (unlisted tools are blocked).');
  console.log("");
  installShutdown(servers, gateway);
}

async function mcpStdio(argv: string[]): Promise<void> {
  // stdout carries the MCP protocol: every log line must go to stderr.
  console.log = (...args: unknown[]) => console.error(...args);
  console.info = console.log;

  const sep = argv.indexOf("--");
  if (sep === -1 || sep === argv.length - 1) throw new Error("Usage: agent-gateway-sdk mcp-stdio [options] -- <command> [args...]");
  const { values } = parseArgs({
    args: argv.slice(0, sep),
    options: {
      "wait-seconds": { type: "string" },
      "admin-port": { type: "string" },
      "admin-host": { type: "string" },
      "no-admin": { type: "boolean" },
      "data-dir": { type: "string" },
    },
    strict: true,
  });
  const [command, ...args] = argv.slice(sep + 1);

  const { rulesPath, configPath, dbPath } = dataPaths(values["data-dir"]);
  const adminPort = parsePort(values["admin-port"], "--admin-port") ?? parsePort(process.env.ADMIN_PORT, "ADMIN_PORT") ?? DEFAULT_ADMIN_PORT;
  const adminHost = values["admin-host"] ?? process.env.ADMIN_HOST ?? "127.0.0.1";
  const gateway = createAgentGateway({ port: adminPort, rulesPath, configPath, dbPath, adminPort, adminHost });
  await gateway.ready;

  const servers: Server[] = [];
  if (!values["no-admin"]) {
    const admin = createBaseApp();
    mountAdmin(admin, gateway, process.env.NODE_ENV === "production");
    admin.get("/", (_req: Request, res: Response) => res.redirect("/agent-admin/"));
    try {
      servers.push(await listen(admin, adminPort, adminHost, "Mont admin console"));
    } catch (err) {
      // Another session already serves the console for this data folder; approvals still work
      // from there (and from Telegram / Slack), because they go through the shared database.
      console.error(`[mcp-stdio] admin console not started (${(err as Error).message}); using the existing one.`);
    }
  }

  const proxy = startMcpStdioProxy(gateway, {
    command,
    args,
    shell: process.platform === "win32",
    approvalWaitMs: waitMs(values["wait-seconds"]),
    agentKey: process.env.MONT_AGENT_KEY?.trim() || null,
  });
  const code = await proxy.exited;
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  await gateway.close().catch(() => undefined);
  // Let the last protocol lines reach the client before exiting.
  process.stdout.write("", () => process.exit(code ?? 1));
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (command === "--version" || command === "-v") {
    console.log(packageVersion());
    return;
  }
  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    console.log(usage());
    return;
  }
  if (command === "start") {
    await start(rest);
    return;
  }
  if (command === "mcp-http") {
    await mcpHttp(rest);
    return;
  }
  if (command === "mcp-stdio") {
    await mcpStdio(rest);
    return;
  }
  console.error(`Unknown command "${command}".\n`);
  console.log(usage());
  process.exitCode = 1;
}

process.on("unhandledRejection", (reason: unknown) => {
  console.error("Unhandled promise rejection:", reason);
});

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
