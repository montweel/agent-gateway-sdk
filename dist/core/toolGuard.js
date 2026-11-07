"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMcpGuard = createMcpGuard;
const constants_1 = require("./constants");
const policy_1 = require("./policy");
const rateLimit_1 = require("./rateLimit");
const pendingQueue_1 = require("./pendingQueue");
const utils_1 = require("./utils");
const operatingMode_1 = require("./operatingMode");
const guards_1 = require("./guards");
const workspaces_1 = require("./workspaces");
const crypto_1 = require("./crypto");
const responseGuard_1 = require("./responseGuard");
// Letters, digits, "_", "-", "." (no "..", no "/"), 1-128 chars: what MCP servers use in practice.
const TOOL_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
function createMcpGuard(ctx) {
    const audit = (0, pendingQueue_1.createAudit)(ctx);
    const timed = (p, label) => (0, utils_1.withTimeout)(p, ctx.dbTimeoutMs, label);
    async function check(req) {
        const path = `${constants_1.MCP_TOOL_PATH_PREFIX}${req.toolName}`;
        let caller = null;
        try {
            await ctx.ready;
            if (typeof req.toolName !== "string" || !TOOL_NAME.test(req.toolName) || req.toolName.includes("..")) {
                await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path: `${constants_1.MCP_TOOL_PATH_PREFIX}(invalid)`, status: "BLOCKED", caller: null, userAgent: req.caller.userAgent, detail: "invalid MCP tool name" });
                return { decision: "BLOCK", reason: "Invalid tool name." };
            }
            const args = req.arguments === undefined ? {} : req.arguments;
            if (typeof args !== "object" || args === null || Array.isArray(args)) {
                await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path, status: "BLOCKED", caller: null, userAgent: req.caller.userAgent, detail: "params.arguments is not an object" });
                return { decision: "BLOCK", reason: "params.arguments must be an object." };
            }
            const config = ctx.config.load();
            caller = { ip: (0, rateLimit_1.bucketIp)(req.caller.ip), userAgent: req.caller.userAgent, agentKeyName: null, agentKeyId: null, agentKeyPrefix: null };
            // Workspace: the proxy's selector (header / mount / option) and/or the caller's mws_ key.
            const rawCredential = req.caller.agentKey ?? null;
            const workspaceKey = rawCredential && rawCredential.startsWith(constants_1.WORKSPACE_KEY_PREFIX) ? rawCredential : null;
            const rawKey = workspaceKey ? null : rawCredential;
            const resolved = (0, workspaces_1.resolveWorkspace)(ctx.workspaces, { pathSlug: null, headerSlug: req.workspace ?? null, key: workspaceKey });
            if (!resolved.ok) {
                await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: `mcp ${resolved.reason}` });
                return { decision: "BLOCK", reason: resolved.message };
            }
            const workspace = resolved.workspace;
            const wsId = workspace.id;
            if (!ctx.workspaces.isEntitled(wsId, ctx.license.current().maxWorkspaces)) {
                await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "mcp workspace over the license limit", workspaceId: wsId });
                return { decision: "BLOCK", reason: `Workspace "${workspace.slug}" is beyond this installation's Mont license.` };
            }
            const entry = ctx.workspaces.lookupEntry(wsId, constants_1.MCP_RULE_METHOD, path);
            // Rate limit (per caller, per rule when the rule sets one).
            const custom = typeof entry?.rule.rateLimit === "number" && entry.rule.rateLimit > 0 ? entry.rule.rateLimit : null;
            const rate = custom
                ? ctx.limiters.checkRateLimit(req.caller.ip, custom, (0, workspaces_1.scopedRuleKey)(wsId, entry.key))
                : ctx.limiters.checkRateLimit(req.caller.ip, config.rateLimitPerMinute);
            if (rate.limited) {
                if (rate.firstLimited) {
                    void audit.logRefusal({
                        method: constants_1.MCP_RULE_METHOD,
                        path,
                        status: "RATE_LIMITED",
                        caller,
                        userAgent: caller.userAgent,
                        detail: "mcp tools/call",
                        workspaceId: wsId,
                        snapshot: (0, pendingQueue_1.buildSnapshot)(ctx, { kind: "mcp", body: args, query: {}, headers: {}, callerId: (0, guards_1.callerIdOf)(caller) }),
                    });
                }
                return { decision: "RATE_LIMITED", retryAfterSec: rate.retryAfterSec, reason: `Rate limit of ${custom ?? config.rateLimitPerMinute} calls per minute exceeded.` };
            }
            // Agent key (a workspace's own mws_ key also authenticates the caller for that workspace).
            if (rawKey || (config.requireAgentApiKey && !resolved.authenticatedByKey)) {
                const info = rawKey ? await timed(ctx.agentKeys.verify(rawKey), "agent key lookup") : null;
                if (info && rawKey) {
                    caller.agentKeyName = info.name;
                    caller.agentKeyId = info.id;
                    caller.agentKeyPrefix = rawKey.slice(0, constants_1.AGENT_KEY_PREFIX.length + 4);
                }
                else if (config.requireAgentApiKey && !resolved.authenticatedByKey) {
                    await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "missing or invalid agent key", workspaceId: wsId });
                    return { decision: "BLOCK", reason: "A valid agent API key is required." };
                }
            }
            if (resolved.authenticatedByKey && caller.agentKeyName === null)
                caller.agentKeyName = `workspace:${workspace.slug}`;
            // Kill-switch.
            const blocked = ctx.blocklist.match({ ip: req.caller.ip, agentKeyId: caller.agentKeyId });
            if (blocked) {
                await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: `caller blocked (${blocked.kind})`, workspaceId: wsId });
                return { decision: "BLOCK", reason: "This caller has been blocked by a gateway administrator." };
            }
            // Rules + payload policies on params.arguments (default deny).
            const rule = entry?.rule ?? { mode: "BLOCK", description: "" };
            const rawVerdict = entry ? (0, policy_1.evaluateRule)(rule, { body: args, query: {}, headers: {} }) : { mode: "BLOCK", matched: "default-deny" };
            const { decision: ruleVerdict, shadow } = (0, policy_1.splitShadow)(rawVerdict);
            const moded = (0, operatingMode_1.applyOperatingMode)(ctx, ruleVerdict, constants_1.MCP_RULE_METHOD, "mcp", workspace);
            const callerId = (0, guards_1.callerIdOf)(caller);
            const guard = await ctx.guards.evaluate(entry ? (0, workspaces_1.scopedRuleKey)(wsId, entry.key) : null, entry?.rule ?? null, moded, args, callerId);
            const amount = (0, guards_1.extractAmount)(args);
            const snapshot = () => (0, pendingQueue_1.buildSnapshot)(ctx, { kind: "mcp", body: args, query: {}, headers: {}, callerId });
            try {
                const verdict = guard.decision;
                const why = guard.reason ? `${verdict.matched}: ${guard.reason}` : verdict.matched;
                if (verdict.mode === "BLOCK") {
                    await audit.logRefusal({ method: constants_1.MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: `mcp ${why}`, amount, workspaceId: wsId, snapshot: snapshot() });
                    let reason;
                    if (verdict.matched === "default-deny")
                        reason = `Tool "${req.toolName}" is not allowed by gateway rules.`;
                    else if (verdict.matched === "lockdown")
                        reason = "The gateway is in emergency lockdown: no tool calls are being accepted right now.";
                    else if (verdict.matched === "duplicate")
                        reason = `This "${req.toolName}" call duplicates one already made. ${guard.reason ?? ""}`.trim();
                    else if (verdict.matched === "budget")
                        reason = `The spending budget for "${req.toolName}" has been reached.`;
                    else
                        reason = `Tool "${req.toolName}" was blocked by a gateway policy.`;
                    return { decision: "BLOCK", reason };
                }
                if (verdict.mode === "REQUIRE_APPROVAL") {
                    const queued = await (0, pendingQueue_1.queuePending)(ctx, audit, {
                        kind: "mcp",
                        method: constants_1.MCP_RULE_METHOD,
                        originalPath: path,
                        cleanPath: path,
                        originalBody: JSON.stringify(args),
                        query: {},
                        headers: { "user-agent": req.caller.userAgent },
                        caller,
                        agentReason: req.agentReason ?? null,
                        matched: why,
                        amount,
                        workspace,
                        snapshot: snapshot(),
                    });
                    if (!queued.ok)
                        return { decision: "BLOCK", reason: queued.message };
                    try {
                        await guard.commit(queued.id);
                    }
                    catch (err) {
                        await (0, pendingQueue_1.discardPending)(ctx, queued.id, "Discarded: the duplicate-protection record could not be written.").catch(() => undefined);
                        throw err;
                    }
                    return { decision: "PENDING", actionId: queued.id, expiresAt: queued.expiresAt, workspaceId: wsId };
                }
                await guard.commit(null);
                await audit.logStrict({
                    method: constants_1.MCP_RULE_METHOD,
                    path,
                    status: "ALLOWED",
                    caller,
                    userAgent: caller.userAgent,
                    detail: shadow
                        ? `mcp shadow: would have ${shadow === "BLOCK" ? "blocked" : "held for approval"} (${ruleVerdict.matched})`
                        : verdict.matched === "rule"
                            ? "mcp"
                            : `mcp ${verdict.matched}`,
                    amount,
                    workspaceId: wsId,
                    shadow,
                    snapshot: snapshot(),
                });
                return { decision: "ALLOW", ruleKey: entry.key, workspaceId: wsId };
            }
            finally {
                guard.release();
            }
        }
        catch (err) {
            console.error("[agent-gateway] FAIL-CLOSED (mcp tools/call):", err);
            return { decision: "BLOCK", reason: "The gateway could not safely evaluate this tool call, so it was refused." };
        }
    }
    function awaitDecision(actionId, opts, execute) {
        return new Promise((resolve) => {
            let settled = false;
            let decided = false;
            let poll;
            let timer;
            const finish = (r) => {
                if (settled)
                    return;
                settled = true;
                if (timer)
                    clearTimeout(timer);
                if (poll)
                    clearInterval(poll);
                ctx.mcpWaiters.delete(actionId);
                opts.signal?.removeEventListener("abort", onAbort);
                resolve(r);
            };
            /** Runs the call (with the approver's edited arguments, if any) once a decision to APPROVE is final. */
            const run = async (override) => {
                try {
                    const out = await execute(override);
                    finish(out.ok ? { status: "APPROVED", value: out.value } : { status: "FAILED", value: out.value, error: out.preview });
                    return { ok: out.ok, preview: out.preview };
                }
                catch (err) {
                    const message = err instanceof Error ? err.message : String(err);
                    finish({ status: "FAILED", error: message });
                    return { ok: false, preview: `Tool call failed: ${message}` };
                }
            };
            /** Approved by another process: it marked the row EXECUTING; we run the call and record it. */
            const runForRemoteApproval = async () => {
                decided = true;
                // The approver may have edited the arguments: they travel encrypted on the row.
                let override;
                try {
                    const row = await ctx.db.get("SELECT patch_encrypted FROM pending_actions WHERE id = ?", [actionId]);
                    if (row?.patch_encrypted) {
                        const parsed = JSON.parse((0, crypto_1.decryptPayload)(row.patch_encrypted, ctx.config.replayEncryptionKey()));
                        override = { arguments: parsed.arguments };
                    }
                }
                catch (err) {
                    // Fail closed: never run the unedited call when the approver asked for an edited one.
                    console.error("Could not read the approver's edits for an MCP tool call:", err);
                    const message = "The approver's edits could not be read, so the tool call was not executed.";
                    finish({ status: "FAILED", error: message });
                    await ctx.db
                        .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ? AND status = 'EXECUTING'", [
                        message,
                        actionId,
                    ])
                        .catch(() => undefined);
                    return;
                }
                const out = await run(override);
                const preview = ctx.redactor.text(out.preview).slice(0, 500);
                await ctx.db
                    .run("UPDATE pending_actions SET status = ?, response_preview = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ? AND status = 'EXECUTING'", [
                    out.ok ? "APPROVED" : "FAILED",
                    preview,
                    actionId,
                ])
                    .catch((err) => console.error("Could not record the MCP tool call outcome:", err));
            };
            const handleStatus = async (status) => {
                if (settled || decided)
                    return true;
                if (status === "EXECUTING") {
                    await runForRemoteApproval();
                    return true;
                }
                if (status === "REJECTED") {
                    decided = true;
                    finish({ status: "REJECTED", reason: "Rejected by an approver." });
                    return true;
                }
                if (status === "EXPIRED" || status === undefined) {
                    decided = true;
                    finish({ status: "EXPIRED", reason: "The approval request expired." });
                    return true;
                }
                return false;
            };
            const expire = async (reason) => {
                if (settled || decided)
                    return;
                ctx.mcpWaiters.delete(actionId);
                try {
                    const r = await ctx.db.run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'", [`Expired: ${reason}. The tool call was never executed.`, actionId]);
                    if (r.changes === 0) {
                        // Someone decided at the same moment: honour that decision instead.
                        const row = await ctx.db.get("SELECT status FROM pending_actions WHERE id = ?", [actionId]);
                        if (await handleStatus(row?.status))
                            return;
                    }
                }
                catch (err) {
                    console.error("Could not expire a held MCP tool call:", err);
                }
                decided = true;
                finish({ status: "EXPIRED", reason });
            };
            const onAbort = () => void expire("the agent disconnected while waiting for approval");
            if (opts.signal?.aborted) {
                void (0, pendingQueue_1.discardPending)(ctx, actionId, "Expired: the agent disconnected before approval. The tool call was never executed.").catch(() => undefined);
                finish({ status: "EXPIRED", reason: "the agent disconnected" });
                return;
            }
            opts.signal?.addEventListener("abort", onAbort, { once: true });
            timer = setTimeout(() => void expire(`no decision within ${Math.round(opts.timeoutMs / 1000)} s`), opts.timeoutMs);
            timer.unref();
            // Decisions taken by another process (or by direct DB updates such as revoke) arrive via SQLite.
            let polling = false;
            poll = setInterval(() => {
                if (polling || settled || decided)
                    return;
                polling = true;
                ctx.db
                    .get("SELECT status FROM pending_actions WHERE id = ?", [actionId])
                    .then((row) => handleStatus(row?.status))
                    .catch(() => undefined)
                    .finally(() => {
                    polling = false;
                });
            }, 750);
            poll.unref();
            // Same-process decisions take the fast path and get the result back synchronously.
            let reserved = false;
            ctx.mcpWaiters.set(actionId, {
                reserve() {
                    if (settled || decided)
                        return false;
                    reserved = true;
                    decided = true; // the DB poll and the timeout now leave this call alone
                    return true;
                },
                unreserve() {
                    if (reserved && !settled) {
                        reserved = false;
                        decided = false;
                    }
                },
                async onDecision(decision, override) {
                    if (settled || (decided && !reserved))
                        return { ok: false, preview: "The agent was no longer waiting." };
                    reserved = false;
                    decided = true;
                    if (decision === "REJECT") {
                        finish({ status: "REJECTED", reason: "Rejected by an approver." });
                        return { ok: true, preview: "rejected" };
                    }
                    return run(override);
                },
            });
        });
    }
    function inspectResult(info, result) {
        const settings = ctx.settings.peek().responseGuard;
        try {
            const v = (0, responseGuard_1.inspectMcpResult)(result, settings);
            if (v.action === "pass")
                return { action: "pass", result, message: null };
            const summary = (0, responseGuard_1.describeFindings)(v.findings);
            const blocked = v.action === "block";
            void audit.logRefusal({
                method: constants_1.MCP_RULE_METHOD,
                path: `${constants_1.MCP_TOOL_PATH_PREFIX}${info.toolName}`,
                status: blocked ? "RESPONSE_BLOCKED" : "RESPONSE_SCRUBBED",
                caller: { ip: (0, rateLimit_1.bucketIp)(info.callerIp), userAgent: info.userAgent, agentKeyName: null, agentKeyId: null, agentKeyPrefix: null },
                userAgent: info.userAgent,
                detail: `mcp result ${blocked ? "withheld" : "scrubbed"}: ${summary}`,
                workspaceId: info.workspaceId,
            });
            return blocked
                ? { action: "block", result, message: `Response Policy Violation: the tool result contained ${summary}, so the Mont gateway withheld it.` }
                : { action: "modified", result: v.result, message: null };
        }
        catch (err) {
            console.error("[agent-gateway] FAIL-CLOSED (mcp response guard):", err);
            return { action: "block", result, message: "Response Policy Violation: the tool result could not be inspected, so it was withheld." };
        }
    }
    return { check, awaitDecision, inspectResult, ruleKeyFor: (name) => `${constants_1.MCP_RULE_METHOD} ${constants_1.MCP_TOOL_PATH_PREFIX}${name}` };
}
