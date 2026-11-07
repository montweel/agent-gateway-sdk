"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.cleanAgentReason = cleanAgentReason;
exports.blockMessage = blockMessage;
exports.createInterceptor = createInterceptor;
const express_1 = __importDefault(require("express"));
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const policy_1 = require("./policy");
const proxy_1 = require("./proxy");
const rateLimit_1 = require("./rateLimit");
const pendingQueue_1 = require("./pendingQueue");
const operatingMode_1 = require("./operatingMode");
const guards_1 = require("./guards");
const utils_1 = require("./utils");
/** Cleans the free-text justification an agent may send in x-agent-reason. */
function cleanAgentReason(raw) {
    if (!raw)
        return null;
    // eslint-disable-next-line no-control-regex
    const clean = raw.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
    return clean ? (0, utils_1.truncate)(clean, constants_1.MAX_AGENT_REASON_LENGTH) : null;
}
/** What an agent is told when it is refused. Thresholds stay private; the kind of refusal does not. */
function blockMessage(matched, path, reason) {
    if (matched === "lockdown")
        return "The gateway is in emergency lockdown: no agent requests are being accepted right now.";
    if (matched === "duplicate")
        return `Refused: this looks like a duplicate of an action already sent. ${reason ?? ""}`.trim();
    if (matched === "budget")
        return "Refused: the spending budget for this action has been reached.";
    if (matched.startsWith("tier:"))
        return `This request to ${path} is blocked by a gateway payload policy.`;
    return `Access to ${path} is blocked by gateway rules.`;
}
/**
 * Builds the interceptor that guards every /api/* request.
 *
 * Order, cheapest and least trusting first:
 *   1. loop guard            (x-gateway-hops)
 *   2. IP rate limit         (before any body is read or parsed)
 *   3. agent API key         (401 when required and missing/invalid)
 *   4. kill-switch           (403 for blocked agent keys / IPs)
 *   5. JSON body parsing     (1 MB cap)
 *   6. rule + payload policy (default deny) -> block / queue for approval / allow
 *
 * FAIL-CLOSED CONTRACT. A request is forwarded (next() or the upstream proxy) only after
 * every step above succeeded AND its ALLOWED audit row is durably written. Any thrown
 * error, rejected promise, SQLite error, SQLite lock wait longer than ctx.dbTimeoutMs,
 * policy evaluation error or client disconnect ends the request with 4xx/503 (or a
 * destroyed socket) and nothing is forwarded. There is no code path that calls next()
 * from an error handler.
 */
function createInterceptor(ctx) {
    const timed = (p, label) => (0, utils_1.withTimeout)(p, ctx.dbTimeoutMs, label);
    const audit = (0, pendingQueue_1.createAudit)(ctx);
    const cleanPathOf = (req) => (0, utils_1.normalizePath)(req.originalUrl.split("?")[0]);
    const userAgentOf = (req) => req.get("user-agent") ?? "unknown";
    // Note: req.destroyed turns true as soon as the body has been read, so the socket is what tells
    // us whether the agent is still there.
    const clientGone = (req, res) => Boolean(req.socket?.destroyed) || res.destroyed || res.headersSent || res.writableEnded;
    /** Body bytes were declared but express.json did not parse them (not application/json). */
    function hasUnparsedBody(req) {
        const te = req.headers["transfer-encoding"];
        const len = Number(req.headers["content-length"] ?? "0");
        const declared = te !== undefined || (Number.isFinite(len) && len > 0);
        return declared && !req.is("application/json");
    }
    /** Hands the request on exactly once, and never to a client that has already gone away. */
    async function forward(req, res, next) {
        if (clientGone(req, res))
            return;
        const config = ctx.config.load();
        if (config.targetUrl)
            await (0, proxy_1.proxyToTarget)(req, res, config.targetUrl, config);
        else
            next();
    }
    /** Rule enforcement for a request whose body is already parsed. */
    async function handle(req, res, next, caller, isReplay) {
        try {
            // Internal replay of an approved request: already authorised by a human.
            if (isReplay) {
                await forward(req, res, next);
                return;
            }
            if (caller === null)
                throw new Error("Caller identity missing on a non-replay request.");
            const cleanPath = cleanPathOf(req);
            // Rule lookup (DEFAULT DENY: unlisted = BLOCK). Exact keys win over wildcard keys,
            // method-specific over any-method (see rules.ts).
            const entry = ctx.rules.lookupEntry(req.method, cleanPath);
            const rule = entry?.rule ?? { mode: "BLOCK", description: "" };
            // A policy that reads the body can only be trusted if the body is the JSON we parsed.
            // A text/plain or form body would be invisible to the policy yet still readable by
            // the app behind the gateway, so it is refused rather than waved through.
            if ((0, policy_1.policiesReadBody)(rule) && hasUnparsedBody(req)) {
                await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "non-JSON body on a payload-policy route" });
                (0, utils_1.sendError)(res, 415, "Unsupported Media Type", "This endpoint is guarded by a payload policy and only accepts application/json bodies.");
                return;
            }
            const ruleDecision = entry
                ? (0, policy_1.evaluateRule)(rule, { body: req.body, query: req.query, headers: req.headers })
                : { mode: "BLOCK", matched: "default-deny" };
            // Shop-wide modes (lockdown, approval-only, business hours) on top of the rule...
            const moded = (0, operatingMode_1.applyOperatingMode)(ctx, ruleDecision, req.method, "http");
            // ...then cross-request guards (spending budget, duplicate protection).
            const guard = await ctx.guards.evaluate(entry?.key ?? null, entry?.rule ?? null, moded, req.body, (0, guards_1.callerIdOf)(caller));
            const amount = (0, guards_1.extractAmount)(req.body);
            try {
                const decision = guard.decision;
                const why = guard.reason ? `${decision.matched}: ${guard.reason}` : decision.matched;
                if (decision.mode === "BLOCK") {
                    await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: why, amount });
                    res.status(403).json({ error: "Forbidden", message: blockMessage(decision.matched, cleanPath, guard.reason), path: cleanPath });
                    return;
                }
                if (decision.mode === "REQUIRE_APPROVAL") {
                    const queued = await (0, pendingQueue_1.queuePending)(ctx, audit, {
                        kind: "http",
                        method: req.method,
                        originalPath: req.originalUrl,
                        cleanPath,
                        originalBody: (0, utils_1.extractBody)(req),
                        query: req.query,
                        headers: req.headers,
                        caller,
                        agentReason: cleanAgentReason(req.get(constants_1.AGENT_REASON_HEADER)),
                        matched: why,
                        amount,
                    });
                    if (!queued.ok) {
                        if (queued.retryAfter)
                            res.setHeader("Retry-After", String(queued.retryAfter));
                        (0, utils_1.sendError)(res, queued.status, queued.error, queued.message);
                        return;
                    }
                    try {
                        await guard.commit(queued.id);
                        guard.release();
                    }
                    catch (err) {
                        await (0, pendingQueue_1.discardPending)(ctx, queued.id, "Discarded: the duplicate-protection record could not be written.").catch(() => undefined);
                        throw err;
                    }
                    // The agent may be gone; the row stays so the admin still sees the attempt.
                    if (clientGone(req, res))
                        return;
                    res.status(202).json({
                        status: "PENDING_APPROVAL",
                        approvalId: queued.id,
                        message: "Request queued for human admin approval.",
                        ...(decision.matched !== "rule" && !decision.matched.startsWith("tier:") ? { reason: guard.reason ?? decision.matched } : {}),
                    });
                    return;
                }
                // ALLOW: the budget / duplicate record and the audit row must be durable BEFORE the
                // request leaves the gateway.
                await guard.commit(null);
                guard.release(); // recorded: the next request on this rule may be checked now
                await audit.logStrict({
                    method: req.method,
                    path: cleanPath,
                    status: "ALLOWED",
                    caller,
                    userAgent: caller.userAgent,
                    detail: decision.matched === "rule" ? null : decision.matched,
                    amount,
                });
                await forward(req, res, next);
            }
            finally {
                guard.release();
            }
        }
        catch (err) {
            (0, utils_1.failClosed)(res, "rule enforcement", err);
        }
    }
    const parseJson = express_1.default.json({ limit: constants_1.JSON_BODY_LIMIT });
    return (req, res, next) => {
        void (async () => {
            try {
                // 1. Loop guard: a target that points back at a gateway would recurse forever.
                const hops = Number.parseInt(req.get(constants_1.HOPS_HEADER) ?? "0", 10);
                if (Number.isFinite(hops) && hops >= constants_1.MAX_HOPS) {
                    (0, utils_1.sendError)(res, 508, "Loop Detected", "Too many gateway hops. Check that targetUrl does not point back at a gateway.");
                    return;
                }
                const replayHeader = req.get(constants_1.REPLAY_HEADER);
                const isReplay = Boolean(replayHeader && (0, crypto_1.safeEqualStrings)(replayHeader, ctx.replaySecret));
                let caller = null;
                if (!isReplay) {
                    const config = ctx.config.load();
                    const rawIp = req.ip ?? req.socket.remoteAddress ?? "unknown";
                    // 2. Rate limit BEFORE parsing the body, so a flood costs almost nothing.
                    // A matched rule with its own rateLimit gets a separate "<ip>:<rule key>" bucket;
                    // everything else (no rule, or no custom limit) uses the global bucket.
                    const matched = ctx.rules.lookupEntry(req.method, cleanPathOf(req));
                    const ruleLimit = matched?.rule.rateLimit;
                    const customLimit = typeof ruleLimit === "number" && ruleLimit > 0 ? ruleLimit : null;
                    const effectiveLimit = customLimit ?? config.rateLimitPerMinute;
                    const rate = customLimit
                        ? ctx.limiters.checkRateLimit(rawIp, customLimit, matched.key)
                        : ctx.limiters.checkRateLimit(rawIp, config.rateLimitPerMinute);
                    if (rate.limited) {
                        // One log row per client per window, not one per rejected request.
                        if (rate.firstLimited) {
                            void ctx.ready
                                .then(() => audit.logRefusal({
                                method: req.method,
                                path: cleanPathOf(req),
                                status: "RATE_LIMITED",
                                caller: { ip: (0, rateLimit_1.bucketIp)(rawIp), userAgent: userAgentOf(req), agentKeyName: null, agentKeyId: null, agentKeyPrefix: null },
                                userAgent: userAgentOf(req),
                            }))
                                .catch(() => undefined);
                        }
                        res.setHeader("Retry-After", String(rate.retryAfterSec));
                        res.status(429).json({
                            error: "Too Many Requests",
                            message: `Rate limit of ${effectiveLimit} requests per minute exceeded.`,
                            retryAfterSeconds: rate.retryAfterSec,
                        });
                        return;
                    }
                    // Nothing below may run against a database that failed to start.
                    await ctx.ready;
                    caller = { ip: (0, rateLimit_1.bucketIp)(rawIp), userAgent: userAgentOf(req), agentKeyName: null, agentKeyId: null, agentKeyPrefix: null };
                    // 3. Agent API key. Optional unless requireAgentApiKey is on.
                    const rawKey = ctx.agentKeys.extract(req);
                    if (rawKey || config.requireAgentApiKey) {
                        const info = rawKey ? await timed(ctx.agentKeys.verify(rawKey), "agent key lookup") : null;
                        if (info && rawKey) {
                            caller.agentKeyName = info.name;
                            caller.agentKeyId = info.id;
                            caller.agentKeyPrefix = rawKey.slice(0, constants_1.AGENT_KEY_PREFIX.length + 4);
                        }
                        else if (config.requireAgentApiKey) {
                            await audit.logRefusal({ method: req.method, path: cleanPathOf(req), status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "missing or invalid agent key" });
                            res.setHeader("WWW-Authenticate", 'Bearer realm="agent-gateway"');
                            (0, utils_1.sendError)(res, 401, "Unauthorized", "A valid agent API key is required. Send it as x-agent-key or Authorization: Bearer agk_...");
                            return;
                        }
                    }
                    // 4. Kill-switch: callers blocked via "Revoke & Block Caller".
                    const blocked = ctx.blocklist.match({ ip: rawIp, agentKeyId: caller.agentKeyId });
                    if (blocked) {
                        await audit.logRefusal({
                            method: req.method,
                            path: cleanPathOf(req),
                            status: "BLOCKED",
                            caller,
                            userAgent: caller.userAgent,
                            detail: `caller blocked (${blocked.kind}) by ${blocked.created_by}`,
                        });
                        (0, utils_1.sendError)(res, 403, "Forbidden", "This caller has been blocked by a gateway administrator.");
                        return;
                    }
                }
                else {
                    await ctx.ready;
                }
                // 5. Body parsing (only for requests that passed the checks above)
                parseJson(req, res, (err) => {
                    if (err) {
                        // Malformed JSON, oversized body or bad charset: refused, never forwarded.
                        (0, utils_1.sendCaughtError)(res, err);
                        return;
                    }
                    void handle(req, res, next, caller, isReplay);
                });
            }
            catch (err) {
                (0, utils_1.failClosed)(res, "pre-checks", err);
            }
        })();
    };
}
