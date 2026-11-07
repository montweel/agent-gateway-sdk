"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApprovalService = createApprovalService;
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const policy_1 = require("./policy");
const proxy_1 = require("./proxy");
const notify_1 = require("./notify");
const utils_1 = require("./utils");
const instance_1 = require("./instance");
const guards_1 = require("./guards");
const err = (status, error, message, extra = {}) => ({
    status,
    body: { error, message, ...extra },
});
/** Query object rebuilt from the original (unredacted) path, shaped like Express's simple parser output. */
function queryFromPath(path) {
    const q = path.indexOf("?");
    const out = {};
    if (q === -1)
        return out;
    const params = new URLSearchParams(path.slice(q + 1));
    for (const key of new Set(params.keys())) {
        const all = params.getAll(key);
        out[key] = all.length > 1 ? all : all[0];
    }
    return out;
}
function createApprovalService(ctx) {
    const { db } = ctx;
    async function expireStale() {
        await db.run(`UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL
       WHERE status IN ('PENDING', 'FAILED') AND expires_at IS NOT NULL AND expires_at <= ?`, [Date.now()]);
    }
    function bodyOf(row) {
        try {
            return row.body ? JSON.parse(row.body) : null;
        }
        catch {
            return null;
        }
    }
    async function logDecision(row, status, actorName, detail) {
        await db.run(`INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
            new Date().toISOString(),
            row.method,
            row.path,
            status,
            `decided_by:${actorName}`,
            row.agent_key ?? null,
            row.id,
            row.caller_ip ?? null,
            detail,
            // A revocation (BLOCKED) is not money protected a second time.
            status === "BLOCKED" ? null : (0, guards_1.extractAmount)(bodyOf(row)),
        ]);
    }
    /** Human-approved spend counts toward the rule's budget. Never fails the approval. */
    async function recordApprovedSpend(row, originalBody) {
        try {
            const rulePath = (0, utils_1.normalizePath)(row.path.split("?")[0]);
            const entry = ctx.rules.lookupEntry(row.method, rulePath);
            if (!entry?.rule.budget)
                return;
            const body = originalBody ? JSON.parse(originalBody) : null;
            const callerId = row.agent_key_id !== null ? `key:${row.agent_key_id}` : `ip:${row.caller_ip ?? "unknown"}`;
            await ctx.guards.recordApproved(entry.key, entry.rule, body, row.id, callerId);
        }
        catch (err) {
            console.error(`Could not record the approved spend for action ${row.id}:`, err);
        }
    }
    /** Decrypts the stored original request. Rows queued before encryption existed only have the redacted copy. */
    function original(row) {
        if (row.encrypted_payload === null)
            return { path: row.path, body: row.body, usedRedactedCopy: true };
        const parsed = JSON.parse((0, crypto_1.decryptPayload)(row.encrypted_payload, ctx.config.replayEncryptionKey()));
        if (typeof parsed.path !== "string")
            throw new Error("Payload has no path.");
        return { path: parsed.path, body: typeof parsed.body === "string" ? parsed.body : null, usedRedactedCopy: false };
    }
    /** Replays a claimed (EXECUTING) action and records the outcome. */
    async function execute(row, req, actorName) {
        const id = row.id;
        const config = ctx.config.load();
        const replayToSelf = config.targetUrl === "";
        const baseUrl = replayToSelf ? `http://127.0.0.1:${ctx.port}` : config.targetUrl;
        const saved = (0, utils_1.parseJsonObject)(row.headers);
        const replayHeaders = {};
        if (saved["content-type"])
            replayHeaders["content-type"] = saved["content-type"];
        if (saved["accept"])
            replayHeaders["accept"] = saved["accept"];
        if (saved["user-agent"])
            replayHeaders["user-agent"] = saved["user-agent"];
        const hasBody = req.body !== null && !constants_1.NO_BODY_METHODS.includes(row.method);
        if (hasBody && !replayHeaders["content-type"])
            replayHeaders["content-type"] = "application/json";
        if (replayToSelf)
            replayHeaders[constants_1.REPLAY_HEADER] = ctx.replaySecret;
        const warning = req.usedRedactedCopy && (row.body?.includes(constants_1.REDACTED) || row.path.includes(encodeURIComponent(constants_1.REDACTED)))
            ? `This request was queued before encrypted replay existed, so its sensitive fields were replayed as "${constants_1.REDACTED}".`
            : undefined;
        try {
            const upstream = await fetch(baseUrl + req.path, {
                method: row.method,
                headers: replayHeaders,
                body: hasBody ? req.body : undefined,
                redirect: "manual",
                signal: AbortSignal.timeout(constants_1.UPSTREAM_TIMEOUT_MS),
            });
            const text = (await (0, proxy_1.readCapped)(upstream)).toString("utf-8");
            // The upstream reply is stored and shown to approvers: scrub it like everything else.
            const preview = ctx.redactor.text(`${upstream.status} ${text.slice(0, 500)}`);
            // Done: the secrets are no longer needed, so wipe them for good.
            await db.run("UPDATE pending_actions SET status = 'APPROVED', response_preview = ?, encrypted_payload = NULL WHERE id = ?", [preview, id]);
            await logDecision(row, "APPROVED", actorName, null);
            if (upstream.status < 400)
                await recordApprovedSpend(row, req.body);
            return {
                status: 200,
                body: {
                    success: true,
                    id,
                    status: "APPROVED",
                    decided_by: actorName,
                    replayStatus: upstream.status,
                    response_preview: preview,
                    ...(warning ? { warning } : {}),
                },
            };
        }
        catch (e) {
            // Not put back in the queue: the target may have received the request
            // before the failure, so a human must choose to RETRY.
            const timedOut = (0, proxy_1.isTimeoutError)(e);
            const reason = timedOut ? "the target did not respond in time" : "the target could not be reached";
            console.error("Replay failed:", e);
            await db
                .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ? WHERE id = ?", [`Replay failed: ${reason}.`, id])
                .catch(() => undefined);
            return err(timedOut ? 504 : 502, timedOut ? "Gateway Timeout" : "Bad Gateway", `Replay failed (${reason}). The action is marked FAILED; an admin can retry it.`, { id, status: "FAILED" });
        }
    }
    async function decide(id, decision, actorName) {
        await expireStale();
        const row = await db.get("SELECT * FROM pending_actions WHERE id = ?", [id]);
        if (!row)
            return err(404, "Not Found", `No pending action with id ${id}.`);
        if (row.status === "EXPIRED")
            return err(410, "Gone", `Action ${id} expired before it was decided. The agent must send it again.`);
        // ---- Reject (a PENDING or FAILED action) ----
        if (decision === "REJECT") {
            if (row.status !== "PENDING" && row.status !== "FAILED") {
                return err(409, "Conflict", `Action ${id} is ${row.status} and can no longer be rejected.`);
            }
            const result = await db.run("UPDATE pending_actions SET status = 'REJECTED', decided_by = ?, encrypted_payload = NULL WHERE id = ? AND status = ?", [actorName, id, row.status]);
            if (result.changes === 0)
                return err(409, "Conflict", `Action ${id} was already decided.`);
            await logDecision(row, "REJECTED", actorName, null);
            // A held MCP call gets its answer right away.
            void ctx.mcpWaiters.get(id)?.onDecision("REJECT");
            return { status: 200, body: { success: true, id, status: "REJECTED", decided_by: actorName } };
        }
        if (row.kind === "mcp" && decision === "RETRY") {
            return err(409, "Conflict", `Action ${id} is an MCP tool call; the agent already received the failure. Ask it to call the tool again.`);
        }
        // ---- Approve (PENDING) or Retry (FAILED) ----
        // Lockdown means nothing runs, including requests a human already looked at.
        if (ctx.emergency.current().mode === "lockdown") {
            return err(409, "Conflict", "The gateway is in emergency lockdown, so nothing can be executed. Resume normal mode first, or reject the request.");
        }
        const from = decision === "APPROVE" ? "PENDING" : "FAILED";
        if (row.status !== from) {
            return err(409, "Conflict", decision === "APPROVE"
                ? `Action ${id} is ${row.status}; only PENDING actions can be approved.`
                : `Action ${id} is ${row.status}; only FAILED actions can be retried.`);
        }
        // A caller blocked after this request was queued can never have it executed.
        const blocked = ctx.blocklist.match({ ip: row.caller_ip, agentKeyId: row.agent_key_id });
        if (blocked) {
            return err(409, "Conflict", `The caller of action ${id} has been blocked (${blocked.kind} ${blocked.label ?? blocked.value}). Reject it instead.`);
        }
        let req;
        try {
            req = original(row);
        }
        catch (e) {
            console.error(`Could not decrypt the stored request for action ${id}:`, e);
            await db
                .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ? WHERE id = ?", [
                "The stored request could not be decrypted (was config.json's replayEncryptionKey changed?). Reject it and ask the agent to send it again.",
                id,
            ])
                .catch(() => undefined);
            return err(500, "Internal Server Error", "The stored request could not be decrypted. Reject it and have the agent send it again.", {
                id,
                status: "FAILED",
            });
        }
        // The rule (or its payload policies) may have changed while the request waited. Re-check it now
        // against the ORIGINAL payload, so tightening a threshold also stops already-queued requests.
        const rulePath = (0, utils_1.normalizePath)(row.path.split("?")[0]);
        const rule = ctx.rules.lookup(row.method, rulePath);
        if (!rule) {
            return err(409, "Conflict", `${row.method} ${rulePath} no longer has a rule (default deny), so this action cannot run. Reject it instead.`);
        }
        let parsedBody = undefined;
        if (req.body !== null) {
            try {
                parsedBody = JSON.parse(req.body);
            }
            catch {
                parsedBody = undefined;
            }
        }
        const verdict = (0, policy_1.evaluateRule)(rule, {
            body: parsedBody,
            query: queryFromPath(req.path),
            headers: (0, utils_1.parseJsonObject)(row.headers),
        });
        if (verdict.mode === "BLOCK") {
            return err(409, "Conflict", `The rule for ${row.method} ${rulePath} now BLOCKs this request (${verdict.matched}), so it cannot run. Reject it instead.`);
        }
        // A held MCP call in this process is reserved BEFORE the DB claim, so its own DB poll
        // cannot also pick up the EXECUTING status and run the call a second time.
        const localWaiter = row.kind === "mcp" ? ctx.mcpWaiters.get(id) : undefined;
        const reserved = localWaiter ? localWaiter.reserve() : false;
        const claim = await db.run(`UPDATE pending_actions SET status = 'EXECUTING', decided_by = ?
       WHERE id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)`, [actorName, id, from, Date.now()]);
        if (claim.changes === 0) {
            if (reserved)
                localWaiter?.unreserve();
            return err(409, "Conflict", `Action ${id} was already decided or has expired.`);
        }
        if (row.kind === "mcp") {
            const result = await releaseMcp(row, actorName, reserved ? localWaiter : undefined);
            // In-process success, or released to the owning process (which will execute it).
            if (result.status === 200 || result.status === 202)
                await recordApprovedSpend(row, req.body);
            return result;
        }
        return execute(row, req, actorName);
    }
    /** APPROVE for a held MCP tool call: the waiting transport runs the original call now. */
    async function releaseMcp(row, actorName, waiter) {
        const id = row.id;
        if (!waiter && row.owner && row.owner !== ctx.instanceId && (0, instance_1.ownerAlive)(row.owner)) {
            // Another gateway process (e.g. a stdio MCP proxy) holds this call. The row is now
            // EXECUTING; that process sees it on its next poll, runs the call and records the result.
            await logDecision(row, "APPROVED", actorName, "mcp tool call released to its owning process");
            return {
                status: 202,
                body: {
                    success: true,
                    id,
                    status: "EXECUTING",
                    decided_by: actorName,
                    message: "Approved. The gateway process holding this tool call is executing it now.",
                },
            };
        }
        if (!waiter) {
            await db.run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ?", ["Expired: the agent stopped waiting before the approval, so the tool call was not executed.", id]);
            return err(410, "Gone", `The agent is no longer waiting for action ${id}, so it was not executed. It must call the tool again.`);
        }
        const out = await waiter.onDecision("APPROVE");
        const preview = ctx.redactor.text(out.preview).slice(0, 500);
        await db.run("UPDATE pending_actions SET status = ?, response_preview = ?, encrypted_payload = NULL WHERE id = ?", [out.ok ? "APPROVED" : "FAILED", preview, id]);
        await logDecision(row, "APPROVED", actorName, out.ok ? "mcp tool call executed" : "mcp tool call failed");
        if (!out.ok)
            return err(502, "Bad Gateway", `The tool call was approved but failed: ${preview}`, { id, status: "FAILED" });
        return { status: 200, body: { success: true, id, status: "APPROVED", decided_by: actorName, response_preview: preview } };
    }
    async function fireRollback(row, actorName, reason, revokedAt) {
        const { url, secret } = ctx.settings.get().rollback;
        if (!url)
            return "NOT_CONFIGURED";
        let body = null;
        try {
            body = row.body ? JSON.parse(row.body) : null;
        }
        catch {
            body = row.body;
        }
        let query = {};
        try {
            query = row.query_json ? JSON.parse(row.query_json) : {};
        }
        catch {
            query = {};
        }
        const payload = JSON.stringify({
            event: "approval.revoked",
            originalRequestId: row.id,
            method: row.method,
            path: row.path,
            // The redacted copy: the unredacted original was wiped when the action was decided.
            body,
            query,
            caller: { ip: row.caller_ip, userAgent: row.caller_ua, agentKey: row.agent_key, agentKeyPrefix: row.agent_key_prefix },
            agentReason: row.agent_reason,
            approvedBy: row.decided_by,
            approvedAt: row.timestamp,
            upstreamResponsePreview: row.response_preview,
            revokedBy: actorName,
            revokedAt,
            reason,
        });
        const ts = String(Math.floor(Date.now() / 1000));
        const headers = {
            "content-type": "application/json",
            "x-mont-event": "approval.revoked",
            "x-mont-timestamp": ts,
            "idempotency-key": `mont-revoke-${row.id}`,
        };
        if (secret)
            headers["x-mont-signature"] = `sha256=${(0, notify_1.signWebhookBody)(secret, ts, payload)}`;
        try {
            const res = await fetch(url, {
                method: "POST",
                headers,
                body: payload,
                redirect: "error",
                signal: AbortSignal.timeout(constants_1.ROLLBACK_TIMEOUT_MS),
            });
            await res.body?.cancel().catch(() => undefined);
            return res.ok ? `SENT ${res.status}` : `FAILED HTTP ${res.status}`;
        }
        catch (e) {
            return `FAILED ${(0, proxy_1.isTimeoutError)(e) ? "timeout" : "unreachable"}`;
        }
    }
    async function revoke(id, options, actorName) {
        const row = await db.get("SELECT * FROM pending_actions WHERE id = ?", [id]);
        if (!row)
            return err(404, "Not Found", `No action with id ${id}.`);
        // FAILED is included: a failed replay may still have reached the target.
        if (row.status !== "APPROVED" && row.status !== "FAILED") {
            return err(409, "Conflict", `Action ${id} is ${row.status}. Only approved (or failed) actions can be revoked; reject pending ones instead.`);
        }
        if (row.revoked_at)
            return err(409, "Conflict", `Action ${id} was already revoked by ${row.revoked_by ?? "an admin"}.`);
        // (a) Kill-switch first: the most important effect must not depend on the rest succeeding.
        const blocks = [];
        if (options.blockAgentKey && row.agent_key_id !== null) {
            blocks.push({ kind: "agent_key", value: String(row.agent_key_id), label: row.agent_key ? `${row.agent_key}${row.agent_key_prefix ? ` (${row.agent_key_prefix}…)` : ""}` : null });
        }
        if (options.blockIp && row.caller_ip)
            blocks.push({ kind: "ip", value: row.caller_ip, label: row.caller_ip });
        if (blocks.length === 0) {
            return err(400, "Bad Request", "Nothing to block: this action has no recorded agent key or IP for the options chosen.");
        }
        const blocked = await ctx.blocklist.add(blocks, {
            createdBy: actorName,
            reason: options.reason,
            sourceActionId: row.id,
        });
        const revokedAt = new Date().toISOString();
        const claim = await db.run("UPDATE pending_actions SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL", [revokedAt, actorName, id]);
        if (claim.changes === 0)
            return err(409, "Conflict", `Action ${id} was revoked concurrently.`);
        // (b) Auto-reject everything this caller still has waiting.
        const keyId = blocks.some((b) => b.kind === "agent_key") ? row.agent_key_id : null;
        const ip = blocks.some((b) => b.kind === "ip") ? row.caller_ip : null;
        const waiting = await db.all(`SELECT * FROM pending_actions
       WHERE status IN ('PENDING', 'FAILED') AND id != ?
         AND ((? IS NOT NULL AND agent_key_id = ?) OR (? IS NOT NULL AND caller_ip = ?))`, [id, keyId, keyId, ip, ip]);
        const autoRejected = [];
        for (const w of waiting) {
            const r = await db.run("UPDATE pending_actions SET status = 'REJECTED', decided_by = ?, encrypted_payload = NULL WHERE id = ? AND status = ?", [`auto:caller-blocked-by:${actorName}`, w.id, w.status]);
            if (r.changes > 0) {
                autoRejected.push(w.id);
                void ctx.mcpWaiters.get(w.id)?.onDecision("REJECT");
                await logDecision(w, "REJECTED", `auto:caller-blocked-by:${actorName}`, `Auto-rejected: caller blocked when action #${id} was revoked.`);
            }
        }
        // (c) Compensating rollback webhook.
        const rollbackStatus = options.fireRollback ? await fireRollback(row, actorName, options.reason, revokedAt) : "SKIPPED";
        await db.run("UPDATE pending_actions SET rollback_status = ? WHERE id = ?", [rollbackStatus, id]);
        await logDecision(row, "BLOCKED", actorName, `Revoked approval #${id}; blocked ${blocked.map((b) => `${b.kind}:${b.label ?? b.value}`).join(", ")}; auto-rejected ${autoRejected.length}; rollback ${rollbackStatus}.`);
        return {
            status: 200,
            body: {
                success: true,
                id,
                revokedAt,
                revokedBy: actorName,
                blocked,
                autoRejected,
                rollbackStatus,
            },
        };
    }
    return { expireStale, decide, revoke };
}
