/**
 * MCP tool-call proxy mode.
 *
 * Puts Mont between an MCP client (Claude Desktop, Cursor, an agent framework, ...) and an MCP
 * server. Every JSON-RPC 2.0 `tools/call` is checked by gateway.mcp before it reaches the server:
 *
 *   rule key   "MCP /api/mcp/tools/<params.name>"     e.g. "MCP /api/mcp/tools/refund_order"
 *   payload    params.arguments  -> "body.*" fields   e.g. { "field": "body.amount", "op": ">", "value": 100 }
 *   plus       rate limits, kill-switch, SQLite audit log, approval queue + phone approvals
 *
 * Unlisted tools are blocked (default deny). Everything else (initialize, tools/list, resources,
 * prompts, notifications, server->client messages) passes through untouched.
 *
 * Refusals come back as a normal tool result with isError: true, so the model reads why the call
 * did not run instead of the client treating it as a transport failure. A call that needs
 * approval is held open until someone decides (or approvalWaitMs passes, then it expires and can
 * never run later).
 *
 * Transports:
 *   createMcpHttpProxy(gateway, { upstreamUrl })   Streamable HTTP (POST JSON / SSE responses, GET SSE, DELETE)
 *   startMcpStdioProxy(gateway, { command, args }) newline-delimited JSON-RPC over stdio (spawns the server)
 */
import express from "express";
import type { Request, Response, Router } from "express";
import { spawn } from "child_process";
import readline from "readline";
import { Readable } from "stream";
import type { Writable } from "stream";
import type { AgentGateway } from "./gateway";
import type { ExecuteOutcome, McpGuard } from "./core/toolGuard";
import { AGENT_KEY_HEADER, AGENT_KEY_PREFIX, AGENT_REASON_HEADER, HOP_BY_HOP, NEVER_FORWARD } from "./core/constants";
import { readCapped, isTimeoutError } from "./core/proxy";
import { cleanAgentReason } from "./core/interceptor";

export const DEFAULT_APPROVAL_WAIT_MS = 5 * 60_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120_000;

type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: JsonRpcId;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

export interface McpCaller {
  ip: string;
  userAgent: string;
  agentKey: string | null;
  reason: string | null;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function isToolsCall(m: unknown): m is JsonRpcMessage & { method: "tools/call" } {
  return isObject(m) && m.method === "tools/call";
}

/** A tool result the model can read (MCP: tool errors are results with isError: true). */
export function toolRefusal(id: JsonRpcId, text: string, decision: string, extra: Record<string, unknown> = {}): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text }],
      isError: true,
      _meta: { "mont/decision": decision, ...extra },
    },
  };
}

export function rpcError(id: JsonRpcId, code: number, message: string): JsonRpcMessage {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export type GateOutcome<T> =
  | { kind: "forward" }
  | { kind: "respond"; message: JsonRpcMessage }
  | { kind: "executed"; value: T };

/**
 * Decides one tools/call. "forward" = send it on now; "respond" = answer with this message;
 * "executed" = it was held, approved and already sent upstream by `executeLater`.
 */
export async function gateToolCall<T>(
  guard: McpGuard,
  msg: JsonRpcMessage,
  caller: McpCaller,
  opts: { approvalWaitMs: number; signal?: AbortSignal },
  executeLater: () => Promise<ExecuteOutcome<T>>
): Promise<GateOutcome<T>> {
  const id = msg.id ?? null;
  const params = isObject(msg.params) ? msg.params : null;
  if (!params || typeof params.name !== "string") {
    return { kind: "respond", message: rpcError(id, -32602, "tools/call needs params.name (string).") };
  }
  const meta = isObject(params._meta) ? params._meta : {};
  const reason = caller.reason ?? (typeof meta["mont/reason"] === "string" ? cleanAgentReason(meta["mont/reason"]) : null);

  const verdict = await guard.check({
    toolName: params.name,
    arguments: params.arguments,
    caller: { ip: caller.ip, userAgent: caller.userAgent, agentKey: caller.agentKey },
    agentReason: reason,
  });

  switch (verdict.decision) {
    case "ALLOW":
      return { kind: "forward" };
    case "BLOCK":
      return { kind: "respond", message: toolRefusal(id, `Blocked by the Mont gateway: ${verdict.reason}`, "BLOCK") };
    case "RATE_LIMITED":
      return {
        kind: "respond",
        message: toolRefusal(id, `Rate-limited by the Mont gateway: ${verdict.reason} Retry in ${verdict.retryAfterSec} s.`, "RATE_LIMITED", {
          "mont/retryAfterSeconds": verdict.retryAfterSec,
        }),
      };
    case "PENDING": {
      const waited = await guard.awaitDecision(verdict.actionId, { timeoutMs: opts.approvalWaitMs, signal: opts.signal }, executeLater);
      if (waited.status === "APPROVED") return { kind: "executed", value: waited.value };
      if (waited.status === "FAILED") {
        if (waited.value !== undefined) return { kind: "executed", value: waited.value };
        return { kind: "respond", message: toolRefusal(id, `Approved, but the tool call failed: ${waited.error}`, "FAILED", { "mont/approvalId": verdict.actionId }) };
      }
      return {
        kind: "respond",
        message: toolRefusal(
          id,
          waited.status === "REJECTED"
            ? `A human reviewer rejected this tool call (approval #${verdict.actionId}). Do not retry it.`
            : `This tool call needed human approval and none was given in time (approval #${verdict.actionId}). It was not executed.`,
          waited.status,
          { "mont/approvalId": verdict.actionId }
        ),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Streamable HTTP
// ---------------------------------------------------------------------------
export interface McpHttpProxyOptions {
  /** The real MCP server endpoint, e.g. http://127.0.0.1:9000/mcp */
  upstreamUrl: string;
  /** How long a held tool call waits for a human. Default 5 minutes. */
  approvalWaitMs?: number;
  /** Upstream timeout per request. Default 120 s. */
  upstreamTimeoutMs?: number;
}

const SKIP_RESPONSE_HEADERS = new Set([...HOP_BY_HOP, "content-length", "content-encoding"]);

function upstreamHeaders(req: Request): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    if (value === undefined || HOP_BY_HOP.has(k) || NEVER_FORWARD.has(k) || k === AGENT_REASON_HEADER) continue;
    const v = Array.isArray(value) ? value.join(", ") : value;
    if (k === "authorization" && v.toLowerCase().startsWith(`bearer ${AGENT_KEY_PREFIX}`)) continue;
    headers.set(k, v);
  }
  return headers;
}

function agentKeyOf(req: Request): string | null {
  const header = req.get(AGENT_KEY_HEADER)?.trim();
  if (header) return header;
  const auth = req.get("authorization")?.trim();
  if (auth && auth.toLowerCase().startsWith("bearer ")) {
    const bearer = auth.slice(7).trim();
    if (bearer.startsWith(AGENT_KEY_PREFIX)) return bearer;
  }
  return null;
}

interface UpstreamReply {
  status: number;
  headers: Array<[string, string]>;
  payload: Buffer;
}

function sendReply(res: Response, r: UpstreamReply): void {
  if (res.headersSent) return;
  res.status(r.status);
  for (const [k, v] of r.headers) if (!SKIP_RESPONSE_HEADERS.has(k.toLowerCase())) res.setHeader(k, v);
  res.send(r.payload);
}

function sendRpc(res: Response, message: JsonRpcMessage, status = 200): void {
  if (res.headersSent) return;
  res.status(status).json(message);
}

export function createMcpHttpProxy(gateway: AgentGateway, opts: McpHttpProxyOptions): Router {
  const router = express.Router();
  const upstream = new URL(opts.upstreamUrl).toString();
  const waitMs = opts.approvalWaitMs ?? DEFAULT_APPROVAL_WAIT_MS;
  const timeoutMs = opts.upstreamTimeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
  const parse = express.json({ limit: "1mb", type: ["application/json", "application/*+json"] });

  async function post(req: Request, body: unknown): Promise<UpstreamReply> {
    const headers = upstreamHeaders(req);
    headers.set("content-type", "application/json");
    const up = await fetch(upstream, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const payload = await readCapped(up);
    const outHeaders: Array<[string, string]> = [];
    up.headers.forEach((v, k) => outHeaders.push([k, v]));
    return { status: up.status, headers: outHeaders, payload };
  }

  const upstreamFailure = (res: Response, id: JsonRpcId, err: unknown): void => {
    console.error("[mcp-proxy] upstream error:", err);
    sendRpc(res, rpcError(id, -32603, isTimeoutError(err) ? "The MCP server did not respond in time." : "Could not reach the MCP server."), 502);
  };

  router.post("/", (req: Request, res: Response) => {
    parse(req, res, (parseErr?: unknown) => {
      void (async () => {
        if (parseErr) {
          sendRpc(res, rpcError(null, -32700, "Parse error: the body must be valid JSON."), 400);
          return;
        }
        if (!req.is("application/json") && !req.is("application/*+json")) {
          sendRpc(res, rpcError(null, -32700, "Content-Type must be application/json."), 415);
          return;
        }
        const body: unknown = req.body;

        // Batches (older protocol versions): pass through unless they hide a tool call.
        if (Array.isArray(body)) {
          if (body.some(isToolsCall)) {
            sendRpc(res, rpcError(null, -32600, "The Mont gateway does not accept tools/call inside a JSON-RPC batch. Send tool calls individually."), 400);
            return;
          }
          try {
            sendReply(res, await post(req, body));
          } catch (err) {
            upstreamFailure(res, null, err);
          }
          return;
        }

        if (!isToolsCall(body)) {
          try {
            sendReply(res, await post(req, body));
          } catch (err) {
            upstreamFailure(res, isObject(body) ? ((body.id as JsonRpcId) ?? null) : null, err);
          }
          return;
        }

        const msg = body as JsonRpcMessage;
        if (msg.id === undefined) {
          // A tool call sent as a notification could never be answered; refuse it outright.
          res.status(400).end();
          return;
        }

        const clientGone = new AbortController();
        res.on("close", () => {
          if (!res.writableFinished) clientGone.abort();
        });

        const caller: McpCaller = {
          ip: req.ip ?? req.socket.remoteAddress ?? "unknown",
          userAgent: req.get("user-agent") ?? "mcp-client",
          agentKey: agentKeyOf(req),
          reason: cleanAgentReason(req.get(AGENT_REASON_HEADER)),
        };

        const outcome = await gateToolCall<UpstreamReply>(gateway.mcp, msg, caller, { approvalWaitMs: waitMs, signal: clientGone.signal }, async () => {
          try {
            const reply = await post(req, msg);
            return { ok: reply.status < 400, preview: `${reply.status} ${reply.payload.toString("utf8").slice(0, 400)}`, value: reply };
          } catch (err) {
            const message = isTimeoutError(err) ? "the MCP server did not respond in time" : "the MCP server could not be reached";
            return {
              ok: false,
              preview: message,
              value: { status: 200, headers: [["content-type", "application/json"]], payload: Buffer.from(JSON.stringify(toolRefusal(msg.id ?? null, `Approved, but ${message}.`, "FAILED"))) },
            };
          }
        });

        if (outcome.kind === "respond") {
          sendRpc(res, outcome.message);
          return;
        }
        if (outcome.kind === "executed") {
          sendReply(res, outcome.value);
          return;
        }
        try {
          sendReply(res, await post(req, msg));
        } catch (err) {
          upstreamFailure(res, msg.id ?? null, err);
        }
      })().catch((err: unknown) => {
        console.error("[mcp-proxy] FAIL-CLOSED:", err);
        sendRpc(res, rpcError(null, -32603, "The gateway hit an error; the request was not forwarded."), 503);
      });
    });
  });

  // Server -> client stream (GET) and session termination (DELETE): straight passthrough.
  const passthrough = (method: "GET" | "DELETE") => async (req: Request, res: Response) => {
    const ac = new AbortController();
    res.on("close", () => ac.abort());
    try {
      const up = await fetch(upstream, { method, headers: upstreamHeaders(req), redirect: "manual", signal: ac.signal });
      res.status(up.status);
      up.headers.forEach((v, k) => {
        if (!SKIP_RESPONSE_HEADERS.has(k.toLowerCase())) res.setHeader(k, v);
      });
      if (!up.body) {
        res.end();
        return;
      }
      res.flushHeaders();
      Readable.fromWeb(up.body as import("stream/web").ReadableStream).on("error", () => res.end()).pipe(res);
    } catch (err) {
      if (ac.signal.aborted) return;
      console.error("[mcp-proxy] upstream stream error:", err);
      if (!res.headersSent) res.status(502).end();
      else res.end();
    }
  };
  router.get("/", (req, res) => void passthrough("GET")(req, res));
  router.delete("/", (req, res) => void passthrough("DELETE")(req, res));

  return router;
}

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------
export interface McpStdioProxyOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Run the command through the system shell (needed for npx / .cmd shims on Windows). */
  shell?: boolean;
  approvalWaitMs?: number;
  /** Optional agent key for this local client (env MONT_AGENT_KEY in the CLI). */
  agentKey?: string | null;
  /** Client side of the protocol. Defaults to process.stdin / process.stdout. */
  input?: Readable;
  output?: Writable;
}

export interface McpStdioProxy {
  /** Resolves with the child's exit code when the server process ends. */
  exited: Promise<number | null>;
  stop(): void;
}

export function startMcpStdioProxy(gateway: AgentGateway, opts: McpStdioProxyOptions): McpStdioProxy {
  const input = opts.input ?? process.stdin;
  const output = opts.output ?? process.stdout;
  const waitMs = opts.approvalWaitMs ?? DEFAULT_APPROVAL_WAIT_MS;
  const shutdown = new AbortController();

  const child = spawn(opts.command, opts.args ?? [], {
    cwd: opts.cwd,
    env: opts.env ?? process.env,
    stdio: ["pipe", "pipe", "inherit"],
    shell: opts.shell ?? false,
    windowsHide: true,
  });

  let clientName = "mcp-stdio-client";
  const toClient = (m: JsonRpcMessage): void => {
    output.write(`${JSON.stringify(m)}\n`);
  };
  const toServer = (m: unknown): void => {
    if (child.stdin.writable) child.stdin.write(`${JSON.stringify(m)}\n`);
  };

  // Responses we are waiting for (approved calls), keyed by JSON-encoded id.
  const awaiting = new Map<string, (m: JsonRpcMessage) => void>();

  // Server -> client: pass every line through unchanged; note responses to approved calls.
  readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
    output.write(`${line}\n`);
    try {
      const m = JSON.parse(line) as JsonRpcMessage;
      if (isObject(m) && m.method === undefined && m.id !== undefined) {
        const key = JSON.stringify(m.id);
        const resolve = awaiting.get(key);
        if (resolve) {
          awaiting.delete(key);
          resolve(m);
        }
      }
    } catch {
      // not JSON: already passed through
    }
  });

  async function handleToolCall(msg: JsonRpcMessage): Promise<void> {
    const caller: McpCaller = { ip: "stdio", userAgent: clientName, agentKey: opts.agentKey ?? null, reason: null };
    const outcome = await gateToolCall<null>(gateway.mcp, msg, caller, { approvalWaitMs: waitMs, signal: shutdown.signal }, () => {
      // Approved: send the ORIGINAL call to the server; its response flows back through the passthrough.
      return new Promise<ExecuteOutcome<null>>((resolve) => {
        const key = JSON.stringify(msg.id);
        const timer = setTimeout(() => {
          awaiting.delete(key);
          resolve({ ok: false, preview: "The MCP server did not answer within 120 s.", value: null });
        }, DEFAULT_UPSTREAM_TIMEOUT_MS);
        timer.unref();
        awaiting.set(key, (m) => {
          clearTimeout(timer);
          const failed = m.error !== undefined || (isObject(m.result) && m.result.isError === true);
          resolve({ ok: !failed, preview: JSON.stringify(m.result ?? m.error).slice(0, 400), value: null });
        });
        toServer(msg);
      });
    });
    if (outcome.kind === "forward") toServer(msg);
    else if (outcome.kind === "respond") toClient(outcome.message);
    // "executed": the server's own response has already been passed through.
  }

  // Tool calls still being evaluated / executed. On client EOF they are drained before the
  // server's stdin is closed, so an allowed call is never dropped on the floor.
  const inflight = new Set<Promise<void>>();

  // Client -> server.
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  rl.on("line", (rawLine) => {
    const line = rawLine.replace(/^﻿/, ""); // tolerate a byte-order mark from Windows shells
    if (line.trim() === "") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Never forward bytes we could not evaluate.
      toClient(rpcError(null, -32700, "Parse error: each line must be one JSON-RPC message."));
      return;
    }
    if (Array.isArray(parsed)) {
      if (parsed.some(isToolsCall)) {
        toClient(rpcError(null, -32600, "The Mont gateway does not accept tools/call inside a JSON-RPC batch."));
        return;
      }
      toServer(parsed);
      return;
    }
    if (!isObject(parsed)) {
      toClient(rpcError(null, -32600, "Invalid JSON-RPC message."));
      return;
    }
    const msg = parsed as JsonRpcMessage;
    if (msg.method === "initialize" && isObject(msg.params) && isObject(msg.params.clientInfo)) {
      const ci = msg.params.clientInfo;
      if (typeof ci.name === "string") clientName = `${ci.name}${typeof ci.version === "string" ? `/${ci.version}` : ""} (mcp stdio)`.slice(0, 200);
    }
    if (isToolsCall(msg)) {
      if (msg.id === undefined) {
        process.stderr.write("[mcp-proxy] dropped a tools/call sent as a notification (no id)\n");
        return;
      }
      const p: Promise<void> = handleToolCall(msg)
        .catch((err: unknown) => {
          process.stderr.write(`[mcp-proxy] FAIL-CLOSED: ${String(err)}\n`);
          toClient(toolRefusal(msg.id ?? null, "The gateway hit an error; the tool call was not executed.", "ERROR"));
        })
        .finally(() => inflight.delete(p));
      inflight.add(p);
      return;
    }
    // Re-serialised, so the server sees exactly the message that was evaluated.
    toServer(msg);
  });
  rl.on("close", () => {
    // Held calls cannot be approved once the client is gone: expire them. Calls already
    // allowed (or mid-evaluation) still reach the server before its stdin is closed.
    shutdown.abort();
    void Promise.allSettled([...inflight]).then(() => child.stdin.end());
  });

  const exited = new Promise<number | null>((resolve) => {
    // "close" (not "exit"): fires after the server's stdout is fully drained to the client.
    child.on("close", (code) => {
      shutdown.abort();
      rl.close();
      resolve(code);
    });
    child.on("error", (err) => {
      process.stderr.write(`[mcp-proxy] could not start the MCP server: ${err.message}\n`);
      shutdown.abort();
      rl.close();
      resolve(null);
    });
  });

  return {
    exited,
    stop() {
      shutdown.abort();
      rl.close();
      if (child.exitCode === null) child.kill();
    },
  };
}
