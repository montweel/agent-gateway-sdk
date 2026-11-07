#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
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
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const util_1 = require("util");
const gateway_1 = require("./gateway");
const config_1 = require("./core/config");
const utils_1 = require("./core/utils");
const host_1 = require("./host");
const mcpProxy_1 = require("./mcpProxy");
const DEFAULT_PROXY_PORT = 8080;
const DEFAULT_ADMIN_PORT = 3000;
function packageVersion() {
    try {
        const pkg = JSON.parse(fs_1.default.readFileSync(path_1.default.resolve(__dirname, "..", "package.json"), "utf8"));
        return pkg.version ?? "unknown";
    }
    catch {
        return "unknown";
    }
}
function usage() {
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
  --workspace <slug>   default workspace for calls that do not name one (header x-mont-workspace,
                       a mws_ key, or the /w/<slug><path> endpoint)
  --admin-port, --admin-host, --data-dir   as for start
  Legacy MCP clients (HTTP+SSE, 2024-11-05) connect to http://<host>:<port><path>/sse

Options for mcp-stdio:
  --wait-seconds <n>   as above
  --admin-port <n>     admin console port (default 3000; skipped if busy, e.g. a second session)
  --no-admin           do not start the admin console
  --data-dir <dir>     as for start (share it between sessions to share rules and approvals)
  --workspace <slug>   the client workspace these tool calls belong to (rules, budgets, approvals)
  MONT_AGENT_KEY       optional agent key (agk_...) or workspace key (mws_...) identifying this client
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
function parsePort(value, flag) {
    if (value === undefined || value === "")
        return undefined;
    const n = Number(value);
    if (!Number.isInteger(n) || n < 1 || n > 65535)
        throw new Error(`${flag} must be a port number from 1 to 65535.`);
    return n;
}
async function start(argv) {
    const { values } = (0, util_1.parseArgs)({
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
    const dataDir = path_1.default.resolve(values["data-dir"] ?? process.cwd());
    fs_1.default.mkdirSync(dataDir, { recursive: true });
    const rulesPath = path_1.default.join(dataDir, "rules.json");
    const configPath = path_1.default.join(dataDir, "config.json");
    const dbPath = path_1.default.join(dataDir, "logs.db");
    const savedPort = fs_1.default.existsSync(dbPath) ? await (0, gateway_1.readPersistedListenPort)(dbPath) : null;
    const proxyPort = parsePort(values.port, "--port") ?? parsePort(process.env.PORT, "PORT") ?? savedPort ?? DEFAULT_PROXY_PORT;
    const proxyHost = values.host ?? process.env.HOST ?? "127.0.0.1";
    const adminPort = parsePort(values["admin-port"], "--admin-port") ?? parsePort(process.env.ADMIN_PORT, "ADMIN_PORT") ?? DEFAULT_ADMIN_PORT;
    const adminHost = values["admin-host"] ?? process.env.ADMIN_HOST ?? "127.0.0.1";
    if (adminPort === proxyPort)
        throw new Error(`The admin port and the proxy port are both ${proxyPort}. Pick different ports.`);
    if (values.target !== undefined) {
        const parsed = (0, utils_1.parseTargetUrl)(values.target, proxyPort);
        if (!parsed.ok)
            throw new Error(`--target: ${parsed.message}`);
        const store = (0, config_1.createConfigStore)(configPath, {});
        store.save({ ...store.load(), targetUrl: parsed.url });
        console.log(`Upstream target set to ${parsed.url}`);
    }
    const gateway = (0, gateway_1.createAgentGateway)({ port: proxyPort, rulesPath, configPath, dbPath, adminPort, adminHost });
    await gateway.ready;
    // ---- Public proxy listener ----
    const proxy = (0, host_1.createBaseApp)();
    proxy.use(gateway.discoveryRouter);
    proxy.use(gateway.approvalCallbackRouter);
    proxy.use("/api", gateway.agentGateway);
    // Reached only when a request was ALLOWED but no upstream is configured: refuse, never pretend.
    proxy.use("/api", (_req, res) => {
        (0, utils_1.sendError)(res, 503, "Service Unavailable", "No upstream target is configured. Set one in the admin console (Gateway Setup tab).");
    });
    proxy.use((_req, res) => {
        (0, utils_1.sendError)(res, 404, "Not Found", "Only /api/* is served by this gateway.");
    });
    proxy.use((err, _req, res, _next) => (0, utils_1.sendCaughtError)(res, err));
    // ---- Admin listener ----
    const admin = (0, host_1.createBaseApp)();
    (0, host_1.mountAdmin)(admin, gateway, process.env.NODE_ENV === "production");
    admin.get("/", (_req, res) => res.redirect("/agent-admin/"));
    admin.use((err, _req, res, _next) => (0, utils_1.sendCaughtError)(res, err));
    const servers = [
        await (0, host_1.listen)(proxy, proxyPort, proxyHost, "Mont gateway proxy"),
        await (0, host_1.listen)(admin, adminPort, adminHost, "Mont admin console"),
    ];
    console.log("");
    console.log(`  Agents call:     http://${proxyHost}:${proxyPort}/api/...`);
    console.log(`  Admin console:   http://${adminHost}:${adminPort}/agent-admin/`);
    console.log(`  Data folder:     ${dataDir}`);
    console.log("  By using this SDK you agree to TERMS.md (see https://montweel.com).");
    console.log("");
    (0, host_1.installShutdown)(servers, gateway);
}
function dataPaths(dir) {
    const dataDir = path_1.default.resolve(dir ?? process.cwd());
    fs_1.default.mkdirSync(dataDir, { recursive: true });
    return { dataDir, rulesPath: path_1.default.join(dataDir, "rules.json"), configPath: path_1.default.join(dataDir, "config.json"), dbPath: path_1.default.join(dataDir, "logs.db") };
}
function waitMs(value) {
    if (value === undefined)
        return mcpProxy_1.DEFAULT_APPROVAL_WAIT_MS;
    const n = Number(value);
    if (!Number.isFinite(n) || n < 5 || n > 24 * 3600)
        throw new Error("--wait-seconds must be between 5 and 86400.");
    return Math.round(n * 1000);
}
async function mcpHttp(argv) {
    const { values } = (0, util_1.parseArgs)({
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
            workspace: { type: "string" },
        },
        strict: true,
    });
    if (!values.upstream)
        throw new Error("mcp-http needs --upstream <url> (the real MCP server endpoint).");
    const upstream = new URL(values.upstream);
    if (upstream.protocol !== "http:" && upstream.protocol !== "https:")
        throw new Error("--upstream must be an http(s) URL.");
    const port = parsePort(values.port, "--port") ?? 8090;
    const host = values.host ?? "127.0.0.1";
    const adminPort = parsePort(values["admin-port"], "--admin-port") ?? parsePort(process.env.ADMIN_PORT, "ADMIN_PORT") ?? DEFAULT_ADMIN_PORT;
    const adminHost = values["admin-host"] ?? process.env.ADMIN_HOST ?? "127.0.0.1";
    if (adminPort === port)
        throw new Error(`The admin port and the MCP proxy port are both ${port}.`);
    const mountPath = values.path ?? "/mcp";
    if (!mountPath.startsWith("/"))
        throw new Error("--path must start with /.");
    const { dataDir, rulesPath, configPath, dbPath } = dataPaths(values["data-dir"]);
    const gateway = (0, gateway_1.createAgentGateway)({ port, rulesPath, configPath, dbPath, adminPort, adminHost });
    await gateway.ready;
    const app = (0, host_1.createBaseApp)();
    app.use(gateway.approvalCallbackRouter);
    const mcpRouter = (0, mcpProxy_1.createMcpHttpProxy)(gateway, { upstreamUrl: upstream.toString(), approvalWaitMs: waitMs(values["wait-seconds"]), workspace: values.workspace });
    app.use(mountPath, mcpRouter);
    // Path-prefix workspace routing: http://<host>:<port>/w/<slug><path>
    app.use(`/w/:slug${mountPath}`, mcpRouter);
    app.use((_req, res) => (0, utils_1.sendError)(res, 404, "Not Found", `The MCP endpoint is ${mountPath} (or /w/<workspace>${mountPath}).`));
    const admin = (0, host_1.createBaseApp)();
    (0, host_1.mountAdmin)(admin, gateway, process.env.NODE_ENV === "production");
    admin.get("/", (_req, res) => res.redirect("/agent-admin/"));
    const servers = [await (0, host_1.listen)(app, port, host, "Mont MCP proxy"), await (0, host_1.listen)(admin, adminPort, adminHost, "Mont admin console")];
    console.log("");
    console.log(`  MCP clients connect to: http://${host}:${port}${mountPath}   (legacy SSE clients: ${mountPath}/sse)`);
    console.log(`  Per client workspace:   http://${host}:${port}/w/<slug>${mountPath}`);
    console.log(`  Forwarding to:          ${upstream.toString()}`);
    console.log(`  Admin console:          http://${adminHost}:${adminPort}/agent-admin/`);
    console.log(`  Data folder:            ${dataDir}`);
    console.log('  Allow tools with rules like "MCP /api/mcp/tools/search_orders" (unlisted tools are blocked).');
    console.log("");
    (0, host_1.installShutdown)(servers, gateway);
}
async function mcpStdio(argv) {
    // stdout carries the MCP protocol: every log line must go to stderr.
    console.log = (...args) => console.error(...args);
    console.info = console.log;
    const sep = argv.indexOf("--");
    if (sep === -1 || sep === argv.length - 1)
        throw new Error("Usage: agent-gateway-sdk mcp-stdio [options] -- <command> [args...]");
    const { values } = (0, util_1.parseArgs)({
        args: argv.slice(0, sep),
        options: {
            "wait-seconds": { type: "string" },
            "admin-port": { type: "string" },
            "admin-host": { type: "string" },
            "no-admin": { type: "boolean" },
            "data-dir": { type: "string" },
            workspace: { type: "string" },
        },
        strict: true,
    });
    const [command, ...args] = argv.slice(sep + 1);
    const { rulesPath, configPath, dbPath } = dataPaths(values["data-dir"]);
    const adminPort = parsePort(values["admin-port"], "--admin-port") ?? parsePort(process.env.ADMIN_PORT, "ADMIN_PORT") ?? DEFAULT_ADMIN_PORT;
    const adminHost = values["admin-host"] ?? process.env.ADMIN_HOST ?? "127.0.0.1";
    const gateway = (0, gateway_1.createAgentGateway)({ port: adminPort, rulesPath, configPath, dbPath, adminPort, adminHost });
    await gateway.ready;
    const servers = [];
    if (!values["no-admin"]) {
        const admin = (0, host_1.createBaseApp)();
        (0, host_1.mountAdmin)(admin, gateway, process.env.NODE_ENV === "production");
        admin.get("/", (_req, res) => res.redirect("/agent-admin/"));
        try {
            servers.push(await (0, host_1.listen)(admin, adminPort, adminHost, "Mont admin console"));
        }
        catch (err) {
            // Another session already serves the console for this data folder; approvals still work
            // from there (and from Telegram / Slack), because they go through the shared database.
            console.error(`[mcp-stdio] admin console not started (${err.message}); using the existing one.`);
        }
    }
    const proxy = (0, mcpProxy_1.startMcpStdioProxy)(gateway, {
        command,
        args,
        shell: process.platform === "win32",
        approvalWaitMs: waitMs(values["wait-seconds"]),
        agentKey: process.env.MONT_AGENT_KEY?.trim() || null,
        workspace: values.workspace ?? null,
    });
    const code = await proxy.exited;
    await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))));
    await gateway.close().catch(() => undefined);
    // Let the last protocol lines reach the client before exiting.
    process.stdout.write("", () => process.exit(code ?? 1));
}
async function main() {
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
process.on("unhandledRejection", (reason) => {
    console.error("Unhandled promise rejection:", reason);
});
main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
});
