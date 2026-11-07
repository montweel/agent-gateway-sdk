"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_APPROVAL_WAIT_MS = void 0;
exports.isToolsCall = isToolsCall;
exports.toolRefusal = toolRefusal;
exports.rpcError = rpcError;
exports.gateToolCall = gateToolCall;
exports.createMcpHttpProxy = createMcpHttpProxy;
exports.startMcpStdioProxy = startMcpStdioProxy;
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
const express_1 = __importDefault(require("express"));
const child_process_1 = require("child_process");
const readline_1 = __importDefault(require("readline"));
const stream_1 = require("stream");
const constants_1 = require("./core/constants");
const proxy_1 = require("./core/proxy");
const interceptor_1 = require("./core/interceptor");
exports.DEFAULT_APPROVAL_WAIT_MS = 5 * 60000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120000;
const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function isToolsCall(m) {
    return isObject(m) && m.method === "tools/call";
}
/** A tool result the model can read (MCP: tool errors are results with isError: true). */
function toolRefusal(id, text, decision, extra = {}) {
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
function rpcError(id, code, message) {
    return { jsonrpc: "2.0", id, error: { code, message } };
}
/**
 * Decides one tools/call. "forward" = send it on now; "respond" = answer with this message;
 * "executed" = it was held, approved and already sent upstream by `executeLater`.
 */
async function gateToolCall(guard, msg, caller, opts, executeLater) {
    const id = msg.id ?? null;
    const params = isObject(msg.params) ? msg.params : null;
    if (!params || typeof params.name !== "string") {
        return { kind: "respond", message: rpcError(id, -32602, "tools/call needs params.name (string).") };
    }
    const meta = isObject(params._meta) ? params._meta : {};
    const reason = caller.reason ?? (typeof meta["mont/reason"] === "string" ? (0, interceptor_1.cleanAgentReason)(meta["mont/reason"]) : null);
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
            if (waited.status === "APPROVED")
                return { kind: "executed", value: waited.value };
            if (waited.status === "FAILED") {
                if (waited.value !== undefined)
                    return { kind: "executed", value: waited.value };
                return { kind: "respond", message: toolRefusal(id, `Approved, but the tool call failed: ${waited.error}`, "FAILED", { "mont/approvalId": verdict.actionId }) };
            }
            return {
                kind: "respond",
                message: toolRefusal(id, waited.status === "REJECTED"
                    ? `A human reviewer rejected this tool call (approval #${verdict.actionId}). Do not retry it.`
                    : `This tool call needed human approval and none was given in time (approval #${verdict.actionId}). It was not executed.`, waited.status, { "mont/approvalId": verdict.actionId }),
            };
        }
    }
}
const SKIP_RESPONSE_HEADERS = new Set([...constants_1.HOP_BY_HOP, "content-length", "content-encoding"]);
function upstreamHeaders(req) {
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
        const k = key.toLowerCase();
        if (value === undefined || constants_1.HOP_BY_HOP.has(k) || constants_1.NEVER_FORWARD.has(k) || k === constants_1.AGENT_REASON_HEADER)
            continue;
        const v = Array.isArray(value) ? value.join(", ") : value;
        if (k === "authorization" && v.toLowerCase().startsWith(`bearer ${constants_1.AGENT_KEY_PREFIX}`))
            continue;
        headers.set(k, v);
    }
    return headers;
}
function agentKeyOf(req) {
    const header = req.get(constants_1.AGENT_KEY_HEADER)?.trim();
    if (header)
        return header;
    const auth = req.get("authorization")?.trim();
    if (auth && auth.toLowerCase().startsWith("bearer ")) {
        const bearer = auth.slice(7).trim();
        if (bearer.startsWith(constants_1.AGENT_KEY_PREFIX))
            return bearer;
    }
    return null;
}
function sendReply(res, r) {
    if (res.headersSent)
        return;
    res.status(r.status);
    for (const [k, v] of r.headers)
        if (!SKIP_RESPONSE_HEADERS.has(k.toLowerCase()))
            res.setHeader(k, v);
    res.send(r.payload);
}
function sendRpc(res, message, status = 200) {
    if (res.headersSent)
        return;
    res.status(status).json(message);
}
function createMcpHttpProxy(gateway, opts) {
    const router = express_1.default.Router();
    const upstream = new URL(opts.upstreamUrl).toString();
    const waitMs = opts.approvalWaitMs ?? exports.DEFAULT_APPROVAL_WAIT_MS;
    const timeoutMs = opts.upstreamTimeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
    const parse = express_1.default.json({ limit: "1mb", type: ["application/json", "application/*+json"] });
    async function post(req, body) {
        const headers = upstreamHeaders(req);
        headers.set("content-type", "application/json");
        const up = await fetch(upstream, {
            method: "POST",
            headers,
            body: JSON.stringify(body),
            redirect: "manual",
            signal: AbortSignal.timeout(timeoutMs),
        });
        const payload = await (0, proxy_1.readCapped)(up);
        const outHeaders = [];
        up.headers.forEach((v, k) => outHeaders.push([k, v]));
        return { status: up.status, headers: outHeaders, payload };
    }
    const upstreamFailure = (res, id, err) => {
        console.error("[mcp-proxy] upstream error:", err);
        sendRpc(res, rpcError(id, -32603, (0, proxy_1.isTimeoutError)(err) ? "The MCP server did not respond in time." : "Could not reach the MCP server."), 502);
    };
    router.post("/", (req, res) => {
        parse(req, res, (parseErr) => {
            void (async () => {
                if (parseErr) {
                    sendRpc(res, rpcError(null, -32700, "Parse error: the body must be valid JSON."), 400);
                    return;
                }
                if (!req.is("application/json") && !req.is("application/*+json")) {
                    sendRpc(res, rpcError(null, -32700, "Content-Type must be application/json."), 415);
                    return;
                }
                const body = req.body;
                // Batches (older protocol versions): pass through unless they hide a tool call.
                if (Array.isArray(body)) {
                    if (body.some(isToolsCall)) {
                        sendRpc(res, rpcError(null, -32600, "The Mont gateway does not accept tools/call inside a JSON-RPC batch. Send tool calls individually."), 400);
                        return;
                    }
                    try {
                        sendReply(res, await post(req, body));
                    }
                    catch (err) {
                        upstreamFailure(res, null, err);
                    }
                    return;
                }
                if (!isToolsCall(body)) {
                    try {
                        sendReply(res, await post(req, body));
                    }
                    catch (err) {
                        upstreamFailure(res, isObject(body) ? (body.id ?? null) : null, err);
                    }
                    return;
                }
                const msg = body;
                if (msg.id === undefined) {
                    // A tool call sent as a notification could never be answered; refuse it outright.
                    res.status(400).end();
                    return;
                }
                const clientGone = new AbortController();
                res.on("close", () => {
                    if (!res.writableFinished)
                        clientGone.abort();
                });
                const caller = {
                    ip: req.ip ?? req.socket.remoteAddress ?? "unknown",
                    userAgent: req.get("user-agent") ?? "mcp-client",
                    agentKey: agentKeyOf(req),
                    reason: (0, interceptor_1.cleanAgentReason)(req.get(constants_1.AGENT_REASON_HEADER)),
                };
                const outcome = await gateToolCall(gateway.mcp, msg, caller, { approvalWaitMs: waitMs, signal: clientGone.signal }, async () => {
                    try {
                        const reply = await post(req, msg);
                        return { ok: reply.status < 400, preview: `${reply.status} ${reply.payload.toString("utf8").slice(0, 400)}`, value: reply };
                    }
                    catch (err) {
                        const message = (0, proxy_1.isTimeoutError)(err) ? "the MCP server did not respond in time" : "the MCP server could not be reached";
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
                }
                catch (err) {
                    upstreamFailure(res, msg.id ?? null, err);
                }
            })().catch((err) => {
                console.error("[mcp-proxy] FAIL-CLOSED:", err);
                sendRpc(res, rpcError(null, -32603, "The gateway hit an error; the request was not forwarded."), 503);
            });
        });
    });
    // Server -> client stream (GET) and session termination (DELETE): straight passthrough.
    const passthrough = (method) => async (req, res) => {
        const ac = new AbortController();
        res.on("close", () => ac.abort());
        try {
            const up = await fetch(upstream, { method, headers: upstreamHeaders(req), redirect: "manual", signal: ac.signal });
            res.status(up.status);
            up.headers.forEach((v, k) => {
                if (!SKIP_RESPONSE_HEADERS.has(k.toLowerCase()))
                    res.setHeader(k, v);
            });
            if (!up.body) {
                res.end();
                return;
            }
            res.flushHeaders();
            stream_1.Readable.fromWeb(up.body).on("error", () => res.end()).pipe(res);
        }
        catch (err) {
            if (ac.signal.aborted)
                return;
            console.error("[mcp-proxy] upstream stream error:", err);
            if (!res.headersSent)
                res.status(502).end();
            else
                res.end();
        }
    };
    router.get("/", (req, res) => void passthrough("GET")(req, res));
    router.delete("/", (req, res) => void passthrough("DELETE")(req, res));
    return router;
}
function startMcpStdioProxy(gateway, opts) {
    const input = opts.input ?? process.stdin;
    const output = opts.output ?? process.stdout;
    const waitMs = opts.approvalWaitMs ?? exports.DEFAULT_APPROVAL_WAIT_MS;
    const shutdown = new AbortController();
    const child = (0, child_process_1.spawn)(opts.command, opts.args ?? [], {
        cwd: opts.cwd,
        env: opts.env ?? process.env,
        stdio: ["pipe", "pipe", "inherit"],
        shell: opts.shell ?? false,
        windowsHide: true,
    });
    let clientName = "mcp-stdio-client";
    const toClient = (m) => {
        output.write(`${JSON.stringify(m)}\n`);
    };
    const toServer = (m) => {
        if (child.stdin.writable)
            child.stdin.write(`${JSON.stringify(m)}\n`);
    };
    // Responses we are waiting for (approved calls), keyed by JSON-encoded id.
    const awaiting = new Map();
    // Server -> client: pass every line through unchanged; note responses to approved calls.
    readline_1.default.createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
        output.write(`${line}\n`);
        try {
            const m = JSON.parse(line);
            if (isObject(m) && m.method === undefined && m.id !== undefined) {
                const key = JSON.stringify(m.id);
                const resolve = awaiting.get(key);
                if (resolve) {
                    awaiting.delete(key);
                    resolve(m);
                }
            }
        }
        catch {
            // not JSON: already passed through
        }
    });
    async function handleToolCall(msg) {
        const caller = { ip: "stdio", userAgent: clientName, agentKey: opts.agentKey ?? null, reason: null };
        const outcome = await gateToolCall(gateway.mcp, msg, caller, { approvalWaitMs: waitMs, signal: shutdown.signal }, () => {
            // Approved: send the ORIGINAL call to the server; its response flows back through the passthrough.
            return new Promise((resolve) => {
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
        if (outcome.kind === "forward")
            toServer(msg);
        else if (outcome.kind === "respond")
            toClient(outcome.message);
        // "executed": the server's own response has already been passed through.
    }
    // Tool calls still being evaluated / executed. On client EOF they are drained before the
    // server's stdin is closed, so an allowed call is never dropped on the floor.
    const inflight = new Set();
    // Client -> server.
    const rl = readline_1.default.createInterface({ input, crlfDelay: Infinity });
    rl.on("line", (rawLine) => {
        const line = rawLine.replace(/^﻿/, ""); // tolerate a byte-order mark from Windows shells
        if (line.trim() === "")
            return;
        let parsed;
        try {
            parsed = JSON.parse(line);
        }
        catch {
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
        const msg = parsed;
        if (msg.method === "initialize" && isObject(msg.params) && isObject(msg.params.clientInfo)) {
            const ci = msg.params.clientInfo;
            if (typeof ci.name === "string")
                clientName = `${ci.name}${typeof ci.version === "string" ? `/${ci.version}` : ""} (mcp stdio)`.slice(0, 200);
        }
        if (isToolsCall(msg)) {
            if (msg.id === undefined) {
                process.stderr.write("[mcp-proxy] dropped a tools/call sent as a notification (no id)\n");
                return;
            }
            const p = handleToolCall(msg)
                .catch((err) => {
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
    const exited = new Promise((resolve) => {
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
            if (child.exitCode === null)
                child.kill();
        },
    };
}
