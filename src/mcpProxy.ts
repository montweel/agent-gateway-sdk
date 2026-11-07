/**
 * MCP tool-call proxy mode.
 *
 * Puts Mont between an MCP client (Claude Desktop, Cursor, an agent framework, ...) and an MCP
 * server. Every JSON-RPC 2.0 `tools/call` is checked by gateway.mcp before it reaches the server:
 *
 *   rule key   "MCP /api/mcp/tools/<params.name>"     e.g. "MCP /api/mcp/tools/refund_order"
 *   payload    params.arguments  -> "body.*" fields   e.g. { "field": "body.amount", "op": ">", "value": 100 }
 *   plus       rate limits, kill-switch, SQLite audit log, approval queue + phone approvals,
 *              workspaces (x-mont-workspace, /w/<slug>/ mount, mws_ key), Edit & Approve,
 *              and the outbound response guard on tool results
 *
 * Unlisted tools are blocked (default deny). Everything else (initialize, tools/list, resources,
 * prompts, notifications, server->client messages) passes through untouched.
 *
 * Refusals come back as a normal tool result with isError: true, so the model reads why the call
 * did not run instead of the client treating it as a transport failure. A call that needs
 * approval is held open until someone decides (or approvalWaitMs passes, then it expires and can
 * never run later).
 *
 * Transports (client side):
 *   createMcpHttpProxy(gateway, { upstreamUrl })   Streamable HTTP (POST JSON / SSE responses, GET SSE, DELETE)
 *                                                  + legacy HTTP+SSE (GET /sse + POST /messages?sessionId=...)
 *   startMcpStdioProxy(gateway, { command, args }) newline-delimited JSON-RPC over stdio (spawns the server)
 * The upstream server is always spoken to over Streamable HTTP (HTTP proxy) or stdio (stdio proxy).
 */
import crypto from "crypto";
import express from "express";
import type { Request, Response, Router } from "express";
import { spawn } from "child_process";
import readline from "readline";
import { Readable } from "stream";
import type { Writable } from "stream";
import type { AgentGateway } from "./gateway";
import type { ExecuteOutcome, ExecuteOverride, McpGuard } from "./core/toolGuard";
import { AGENT_KEY_HEADER, AGENT_KEY_PREFIX, AGENT_REASON_HEADER, HOP_BY_HOP, NEVER_FORWARD, WORKSPACE_HEADER, WORKSPACE_KEY_PREFIX } from "./core/constants";
import { readCapped, isTimeoutError } from "./core/proxy";
import { cleanAgentReason } from "./core/interceptor";

export const DEFAULT_APPROVAL_WAIT_MS = 5 * 60_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120_000;
const SSE_KEEPALIVE_MS = 15_000;
const MAX_LEGACY_SESSIONS = 1_000;

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
  /** agk_ agent key or mws_ workspace key. */
  agentKey: string | null;
  reason: string | null;
  /** Workspace slug selector, if any. */
  workspace?: string | null;
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

/** The same tools/call with the approver's edited arguments. */
export function withArguments(msg: JsonRpcMessage, override: ExecuteOverride | undefined): JsonRpcMessage {
  if (!override) return msg;
  const params = isObject(msg.params) ? msg.params : {};
  return { ...msg, params: { ...params, arguments: override.arguments } };
}

export type GateOutcome<T> =
  | { kind: "forward"; workspaceId: number }
  | { kind: "respond"; message: JsonRpcMessage }
  | { kind: "executed"; value: T; workspaceId: number };

/**
 * Decides one tools/call. "forward" = send it on now; "respond" = answer with this message;
 * "executed" = it was held, approved and already sent upstream by `executeLater` (with the
 * approver's edited arguments when they changed them).
 */
export async function gateToolCall<T>(
  guard: McpGuard,
  msg: JsonRpcMessage,
  caller: McpCaller,
  opts: { approvalWaitMs: number; signal?: AbortSignal },
  executeLater: (override: ExecuteOverride | undefined, workspaceId: number) => Promise<ExecuteOutcome<T>>
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
    workspace: caller.workspace ?? null,
  });

  switch (verdict.decision) {
    case "ALLOW":
      return { kind: "forward", workspaceId: verdict.workspaceId };
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
      const waited = await guard.awaitDecision(verdict.actionId, { timeoutMs: opts.approvalWaitMs, signal: opts.signal }, (override) =>
        executeLater(override, verdict.workspaceId)
      );
      if (waited.status === "APPROVED") return { kind: "executed", value: waited.value, workspaceId: verdict.workspaceId };
      if (waited.status === "FAILED") {
        if (waited.value !== undefined) return { kind: "executed", value: waited.value, workspaceId: verdict.workspaceId };
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

/** Applies the outbound response guard to the reply for one tools/call (null = not that call's reply). */
export function guardToolReply(
  guard: McpGuard,
  m: JsonRpcMessage,
  callId: JsonRpcId,
  info: { toolName: string; workspaceId: number; callerIp: string; userAgent: string }
): JsonRpcMessage {
  if (!isObject(m) || m.method !== undefined || m.id !== callId || m.result === undefined) return m;
  const v = guard.inspectResult(info, m.result);
  if (v.action === "block") return toolRefusal(callId, v.message ?? "Response Policy Violation.", "RESPONSE_BLOCKED");
  if (v.action === "modified") return { ...m, result: v.result };
  return m;
}

// ---------------------------------------------------------------------------
// Server-sent events
// ---------------------------------------------------------------------------
export interface SseEvent {
  event: string | null;
  id: string | null;
  data: string;
}

/** Parses a complete text/event-stream body into events (comments and retry lines dropped). */
export function parseSse(text: string): SseEvent[] {
  const events: SseEvent[] = [];
  for (const block of text.replace(/\r\n/g, "\n").split(/\n\n+/)) {
    let event: string | null = null;
    let id: string | null = null;
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line === "" || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "id") id = value;
      else if (field === "data") data.push(value);
    }
    if (data.length > 0) events.push({ event, id, data: data.join("\n") });
  }
  return events;
}

export function formatSse(e: SseEvent): string {
  return `${e.event ? `event: ${e.event}\n` : ""}${e.id ? `id: ${e.id}\n` : ""}${e.data
    .split("\n")
    .map((l) => `data: ${l}`)
    .join("\n")}\n\n`;
}

/** JSON-RPC messages carried by an upstream reply (JSON object / batch, or SSE). */
function messagesOf(contentType: string, payload: Buffer): JsonRpcMessage[] {
  const text = payload.toString("utf8");
  if (/text\/event-stream/i.test(contentType)) {
    const out: JsonRpcMessage[] = [];
    for (const e of parseSse(text)) {
      try {
        const parsed = JSON.parse(e.data) as unknown;
        if (Array.isArray(parsed)) out.push(...(parsed as JsonRpcMessage[]));
        else if (isObject(parsed)) out.push(parsed as JsonRpcMessage);
      } catch {
        // not JSON: ignore
      }
    }
    return out;
  }
  if (text.trim() === "") return [];
  try {
    const parsed = JSON.parse(text) as unknown;
    if (Array.isArray(parsed)) return parsed as JsonRpcMessage[];
    if (isObject(parsed)) return [parsed as JsonRpcMessage];
  } catch {
    // fall through
  }
  return [];
}

// ---------------------------------------------------------------------------
// Streamable HTTP (+ legacy HTTP+SSE)
// ---------------------------------------------------------------------------
export interface McpHttpProxyOptions {
  /** The real MCP server endpoint, e.g. http://127.0.0.1:9000/mcp */
  upstreamUrl: string;
  /** How long a held tool call waits for a human. Default 5 minutes. */
  approvalWaitMs?: number;
  /** Upstream timeout per request. Default 120 s. */
  upstreamTimeoutMs?: number;
  /**
   * Workspace for every call through this router, unless the request names one (x-mont-workspace
   * header, a mws_ key, or a /w/:slug mount: `app.use("/w/:slug/mcp", router)`).
   */
  workspace?: string;
}

const SKIP_RESPONSE_HEADERS = new Set([...HOP_BY_HOP, "content-length", "content-encoding"]);

function upstreamHeaders(req: Request): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    if (value === undefined || HOP_BY_HOP.has(k) || NEVER_FORWARD.has(k) || k === AGENT_REASON_HEADER) continue;
    const v = Array.isArray(value) ? value.join(", ") : value;
    const lower = v.toLowerCase();
    if (k === "authorization" && (lower.startsWith(`bearer ${AGENT_KEY_PREFIX}`) || lower.startsWith(`bearer ${WORKSPACE_KEY_PREFIX}`))) continue;
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
    if (bearer.startsWith(AGENT_KEY_PREFIX) || bearer.startsWith(WORKSPACE_KEY_PREFIX)) return bearer;
  }
  return null;
}

/** Workspace selector for an HTTP request: the /w/:slug mount, then the header, then the router option. */
function workspaceOf(req: Request, fallback: string | undefined): string | null {
  const fromPath = typeof req.params?.slug === "string" ? req.params.slug : null;
  const fromHeader = req.get(WORKSPACE_HEADER)?.trim() || null;
  // Conflicting selectors: a name no workspace can have, so the guard refuses the call.
  if (fromPath && fromHeader && fromPath.toLowerCase() !== fromHeader.toLowerCase()) return "(conflicting workspace selectors)";
  return fromPath ?? fromHeader ?? fallback ?? null;
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

function headerOf(r: UpstreamReply, name: string): string {
  return r.headers.find(([k]) => k.toLowerCase() === name)?.[1] ?? "";
}

/** Rewrites an upstream reply so the result of `callId` passes the response guard. */
function guardReply(guard: McpGuard, r: UpstreamReply, callId: JsonRpcId, info: { toolName: string; workspaceId: number; callerIp: string; userAgent: string }): UpstreamReply {
  const ct = headerOf(r, "content-type");
  const text = r.payload.toString("utf8");
  const rewrite = (m: unknown): unknown => (isObject(m) ? guardToolReply(guard, m as JsonRpcMessage, callId, info) : m);
  if (/text\/event-stream/i.test(ct)) {
    let changed = false;
    const events = parseSse(text).map((e) => {
      try {
        const parsed = JSON.parse(e.data) as unknown;
        const next = Array.isArray(parsed) ? parsed.map(rewrite) : rewrite(parsed);
        const data = JSON.stringify(next);
        if (data !== JSON.stringify(parsed)) changed = true;
        return { ...e, data };
      } catch {
        return e;
      }
    });
    return changed ? { ...r, payload: Buffer.from(events.map(formatSse).join(""), "utf8") } : r;
  }
  if (!/json/i.test(ct)) return r;
  try {
    const parsed = JSON.parse(text) as unknown;
    const next = Array.isArray(parsed) ? parsed.map(rewrite) : rewrite(parsed);
    const out = JSON.stringify(next);
    return out === JSON.stringify(parsed) ? r : { ...r, payload: Buffer.from(out, "utf8") };
  } catch {
    return r;
  }
}

interface LegacySession {
  id: string;
  res: Response;
  closed: AbortController;
  upstreamSessionId: string | null;
  /** Credentials / selectors from the GET /sse request (POSTs may add or override them). */
  agentKey: string | null;
  workspace: string | null;
  ip: string;
  userAgent: string;
  streamStarted: boolean;
  keepalive: NodeJS.Timeout;
}

export function createMcpHttpProxy(gateway: AgentGateway, opts: McpHttpProxyOptions): Router {
  const router = express.Router({ mergeParams: true });
  const upstream = new URL(opts.upstreamUrl).toString();
  const waitMs = opts.approvalWaitMs ?? DEFAULT_APPROVAL_WAIT_MS;
  const timeoutMs = opts.upstreamTimeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
  const parse = express.json({ limit: "1mb", type: ["application/json", "application/*+json"] });
  const sessions = new Map<string, LegacySession>();

  async function post(headers: Headers, body: unknown, signal?: AbortSignal): Promise<UpstreamReply> {
    headers.set("content-type", "application/json");
    if (!headers.has("accept")) headers.set("accept", "application/json, text/event-stream");
    const up = await fetch(upstream, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      redirect: "manual",
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs),
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

  /**
   * Gates one tools/call and returns the upstream reply to send back (guarded), or a JSON-RPC
   * message when the gateway answers itself.
   */
  async function handleToolCall(
    msg: JsonRpcMessage,
    caller: McpCaller,
    makeHeaders: () => Headers,
    signal: AbortSignal
  ): Promise<{ reply: UpstreamReply } | { message: JsonRpcMessage }> {
    const toolName = isObject(msg.params) && typeof msg.params.name === "string" ? msg.params.name : "";
    const callId = msg.id ?? null;
    const outcome = await gateToolCall<UpstreamReply>(gateway.mcp, msg, caller, { approvalWaitMs: waitMs, signal }, async (override) => {
      try {
        const reply = await post(makeHeaders(), withArguments(msg, override));
        return { ok: reply.status < 400, preview: `${reply.status} ${reply.payload.toString("utf8").slice(0, 400)}`, value: reply };
      } catch (err) {
        const message = isTimeoutError(err) ? "the MCP server did not respond in time" : "the MCP server could not be reached";
        return {
          ok: false,
          preview: message,
          value: { status: 200, headers: [["content-type", "application/json"]], payload: Buffer.from(JSON.stringify(toolRefusal(callId, `Approved, but ${message}.`, "FAILED"))) },
        };
      }
    });
    if (outcome.kind === "respond") return { message: outcome.message };
    const info = { toolName, workspaceId: outcome.workspaceId, callerIp: caller.ip, userAgent: caller.userAgent };
    const reply = outcome.kind === "executed" ? outcome.value : await post(makeHeaders(), msg);
    return { reply: guardReply(gateway.mcp, reply, callId, info) };
  }

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
            sendReply(res, await post(upstreamHeaders(req), body));
          } catch (err) {
            upstreamFailure(res, null, err);
          }
          return;
        }

        if (!isToolsCall(body)) {
          try {
            sendReply(res, await post(upstreamHeaders(req), body));
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
          workspace: workspaceOf(req, opts.workspace),
        };

        try {
          const out = await handleToolCall(msg, caller, () => upstreamHeaders(req), clientGone.signal);
          if ("message" in out) sendRpc(res, out.message);
          else sendReply(res, out.reply);
        } catch (err) {
          upstreamFailure(res, msg.id ?? null, err);
        }
      })().catch((err: unknown) => {
        console.error("[mcp-proxy] FAIL-CLOSED:", err);
        sendRpc(res, rpcError(null, -32603, "The gateway hit an error; the request was not forwarded."), 503);
      });
    });
  });

  // ---------------- Legacy HTTP+SSE transport (protocol 2024-11-05) ----------------
  // GET /sse opens the server->client stream; its first event names the POST endpoint.
  // The client POSTs JSON-RPC to /messages?sessionId=...; every answer travels on the stream.
  // Upstream, Mont speaks Streamable HTTP, so old clients reach new servers through it unchanged.

  function writeEvent(s: LegacySession, event: string, data: string): void {
    if (s.closed.signal.aborted || s.res.writableEnded) return;
    s.res.write(formatSse({ event, id: null, data }));
  }

  function closeSession(s: LegacySession): void {
    if (s.closed.signal.aborted) return;
    s.closed.abort();
    clearInterval(s.keepalive);
    sessions.delete(s.id);
    if (!s.res.writableEnded) s.res.end();
    // Best effort: end the upstream session too.
    if (s.upstreamSessionId) {
      void fetch(upstream, { method: "DELETE", headers: { "mcp-session-id": s.upstreamSessionId }, signal: AbortSignal.timeout(5_000) })
        .then((r) => r.body?.cancel())
        .catch(() => undefined);
    }
  }

  /** Server-initiated messages: the upstream's GET stream, relayed onto the legacy SSE stream. */
  function startUpstreamStream(s: LegacySession, headers: Headers): void {
    if (s.streamStarted || !s.upstreamSessionId) return;
    s.streamStarted = true;
    headers.set("accept", "text/event-stream");
    headers.set("mcp-session-id", s.upstreamSessionId);
    void (async () => {
      try {
        const up = await fetch(upstream, { method: "GET", headers, redirect: "manual", signal: s.closed.signal });
        if (!up.ok || !up.body || !/text\/event-stream/i.test(up.headers.get("content-type") ?? "")) {
          await up.body?.cancel().catch(() => undefined);
          return; // the server has no standalone stream (405 is allowed by the spec)
        }
        const decoder = new TextDecoder();
        let buffer = "";
        for await (const chunk of up.body as unknown as AsyncIterable<Uint8Array>) {
          buffer += decoder.decode(chunk, { stream: true }).replace(/\r\n/g, "\n");
          let cut: number;
          while ((cut = buffer.indexOf("\n\n")) !== -1) {
            const block = buffer.slice(0, cut + 2);
            buffer = buffer.slice(cut + 2);
            for (const e of parseSse(block)) writeEvent(s, "message", e.data);
          }
        }
      } catch {
        // stream ended or session closed
      }
    })();
  }

  router.get("/sse", (req: Request, res: Response) => {
    if (sessions.size >= MAX_LEGACY_SESSIONS) {
      res.status(503).json({ error: "Service Unavailable", message: "Too many open MCP SSE sessions." });
      return;
    }
    const id = crypto.randomUUID();
    res.status(200);
    res.setHeader("content-type", "text/event-stream");
    res.setHeader("cache-control", "no-cache, no-transform");
    res.setHeader("connection", "keep-alive");
    res.setHeader("x-accel-buffering", "no");
    res.flushHeaders();
    const session: LegacySession = {
      id,
      res,
      closed: new AbortController(),
      upstreamSessionId: null,
      agentKey: agentKeyOf(req),
      workspace: workspaceOf(req, opts.workspace),
      ip: req.ip ?? req.socket.remoteAddress ?? "unknown",
      userAgent: req.get("user-agent") ?? "mcp-sse-client",
      streamStarted: false,
      keepalive: setInterval(() => {
        if (!res.writableEnded) res.write(": keepalive\n\n");
      }, SSE_KEEPALIVE_MS),
    };
    session.keepalive.unref();
    sessions.set(id, session);
    res.on("close", () => closeSession(session));
    writeEvent(session, "endpoint", `${req.baseUrl}/messages?sessionId=${encodeURIComponent(id)}`);
  });

  router.post("/messages", (req: Request, res: Response) => {
    const sessionId = typeof req.query.sessionId === "string" ? req.query.sessionId : "";
    const s = sessions.get(sessionId);
    if (!s) {
      res.status(404).json({ error: "Not Found", message: "Unknown or closed MCP session. Reconnect to GET /sse." });
      return;
    }
    parse(req, res, (parseErr?: unknown) => {
      if (parseErr || (!req.is("application/json") && !req.is("application/*+json"))) {
        res.status(400).json({ error: "Bad Request", message: "The body must be one JSON-RPC message (application/json)." });
        return;
      }
      const body: unknown = req.body;
      if (Array.isArray(body) ? body.some(isToolsCall) : false) {
        res.status(400).json({ error: "Bad Request", message: "The Mont gateway does not accept tools/call inside a JSON-RPC batch." });
        return;
      }
      if (!Array.isArray(body) && !isObject(body)) {
        res.status(400).json({ error: "Bad Request", message: "Invalid JSON-RPC message." });
        return;
      }
      // Accepted: the answer (if any) arrives on the event stream.
      res.status(202).send("Accepted");

      const msg = body as JsonRpcMessage;
      const postWorkspace = workspaceOf(req, undefined);
      const caller: McpCaller = {
        ip: s.ip,
        userAgent: req.get("user-agent") ?? s.userAgent,
        agentKey: agentKeyOf(req) ?? s.agentKey,
        reason: cleanAgentReason(req.get(AGENT_REASON_HEADER)),
        workspace: postWorkspace ?? s.workspace,
      };
      const makeHeaders = (): Headers => {
        const h = upstreamHeaders(req);
        h.delete("mcp-session-id");
        if (s.upstreamSessionId) h.set("mcp-session-id", s.upstreamSessionId);
        return h;
      };
      const deliver = (reply: UpstreamReply, requestId: JsonRpcId | undefined): void => {
        const sid = headerOf(reply, "mcp-session-id");
        if (sid && !s.upstreamSessionId) s.upstreamSessionId = sid;
        const messages = messagesOf(headerOf(reply, "content-type"), reply.payload);
        if (messages.length === 0 && reply.status >= 400 && requestId !== undefined) {
          writeEvent(s, "message", JSON.stringify(rpcError(requestId, -32603, `The MCP server answered HTTP ${reply.status}.`)));
          return;
        }
        for (const m of messages) writeEvent(s, "message", JSON.stringify(m));
      };

      void (async () => {
        try {
          if (!Array.isArray(body) && isToolsCall(msg)) {
            if (msg.id === undefined) return; // a tool call as a notification can never be answered
            const out = await handleToolCall(msg, caller, makeHeaders, s.closed.signal);
            if ("message" in out) writeEvent(s, "message", JSON.stringify(out.message));
            else deliver(out.reply, msg.id);
            return;
          }
          const reply = await post(makeHeaders(), body, s.closed.signal);
          deliver(reply, Array.isArray(body) ? undefined : msg.id);
          // After initialization, relay server-initiated notifications too.
          if (!Array.isArray(body) && msg.method === "notifications/initialized") startUpstreamStream(s, makeHeaders());
        } catch (err) {
          if (s.closed.signal.aborted) return;
          console.error("[mcp-proxy] legacy SSE upstream error:", err);
          if (!Array.isArray(body) && msg.id !== undefined) {
            writeEvent(s, "message", JSON.stringify(rpcError(msg.id ?? null, -32603, isTimeoutError(err) ? "The MCP server did not respond in time." : "Could not reach the MCP server.")));
          }
        }
      })();
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
  /** Optional agent key (agk_) or workspace key (mws_) for this local client (env MONT_AGENT_KEY in the CLI). */
  agentKey?: string | null;
  /** Workspace slug for every call (CLI --workspace). */
  workspace?: string | null;
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
  // Allowed / approved tool calls whose results must pass the response guard, keyed by JSON-encoded id.
  const guarded = new Map<string, { toolName: string; workspaceId: number }>();

  // Server -> client: pass every line through; tool results go through the response guard first.
  readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
    let m: JsonRpcMessage | null = null;
    try {
      const parsed = JSON.parse(line) as unknown;
      m = isObject(parsed) ? (parsed as JsonRpcMessage) : null;
    } catch {
      m = null;
    }
    if (m && m.method === undefined && m.id !== undefined) {
      const key = JSON.stringify(m.id);
      const g = guarded.get(key);
      if (g) {
        guarded.delete(key);
        const out = guardToolReply(gateway.mcp, m, m.id ?? null, { toolName: g.toolName, workspaceId: g.workspaceId, callerIp: "stdio", userAgent: clientName });
        if (out !== m) {
          output.write(`${JSON.stringify(out)}\n`);
          awaiting.get(key)?.(out);
          awaiting.delete(key);
          return;
        }
      }
      output.write(`${line}\n`);
      const resolve = awaiting.get(key);
      if (resolve) {
        awaiting.delete(key);
        resolve(m);
      }
      return;
    }
    output.write(`${line}\n`); // not a response (or not JSON): passed through unchanged
  });

  async function handleToolCall(msg: JsonRpcMessage): Promise<void> {
    const caller: McpCaller = { ip: "stdio", userAgent: clientName, agentKey: opts.agentKey ?? null, reason: null, workspace: opts.workspace ?? null };
    const toolName = isObject(msg.params) && typeof msg.params.name === "string" ? msg.params.name : "";
    const key = JSON.stringify(msg.id);
    const outcome = await gateToolCall<null>(gateway.mcp, msg, caller, { approvalWaitMs: waitMs, signal: shutdown.signal }, (override, workspaceId) => {
      // Approved: send the call (with the approver's edits) to the server; its response flows back through the passthrough.
      return new Promise<ExecuteOutcome<null>>((resolve) => {
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
        guarded.set(key, { toolName, workspaceId });
        toServer(withArguments(msg, override));
      });
    });
    if (outcome.kind === "forward") {
      guarded.set(key, { toolName, workspaceId: outcome.workspaceId });
      toServer(msg);
    } else if (outcome.kind === "respond") toClient(outcome.message);
    // "executed": the server's own (guarded) response has already been passed through.
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
