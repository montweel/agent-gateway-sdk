"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildSnapshot = buildSnapshot;
exports.createAudit = createAudit;
exports.queuePending = queuePending;
exports.discardPending = discardPending;
const constants_1 = require("./constants");
const constants_2 = require("./constants");
const crypto_1 = require("./crypto");
const utils_1 = require("./utils");
const notify_1 = require("./notify");
const justification_1 = require("./justification");
/** agent_logs / pending_actions.end_user_verified: 1 verified, 0 agent-claimed, NULL no end user. */
const verifiedFlag = (c) => (c?.endUser ? (c.endUserVerified ? 1 : 0) : null);
/**
 * The redacted copy of a request kept with its audit row, so "Test rules against history" can
 * replay it later. Same scrubbing as everything else stored; capped at MAX_SNAPSHOT_CHARS (a
 * larger request keeps its query and headers but is marked truncated).
 */
function buildSnapshot(ctx, s) {
    const headers = ctx.redactor.headers(s.headers);
    const smallHeaders = {};
    for (const [k, v] of Object.entries(headers).slice(0, 40))
        smallHeaders[k] = v.slice(0, 512);
    const base = { v: 1, kind: s.kind, query: ctx.redactor.json((0, utils_1.redactQueryObject)(s.query)), headers: smallHeaders, caller: s.callerId };
    if (s.bodyUnknown)
        return JSON.stringify({ ...base, bodyUnknown: true });
    const full = JSON.stringify({ ...base, body: s.body === undefined ? null : ctx.redactor.json(s.body) });
    if (full.length <= constants_2.MAX_SNAPSHOT_CHARS)
        return full;
    const lean = JSON.stringify({ ...base, truncated: true });
    return lean.length <= constants_2.MAX_SNAPSHOT_CHARS ? lean : JSON.stringify({ v: 1, kind: s.kind, caller: s.callerId, truncated: true });
}
function createAudit(ctx) {
    async function logStrict(e) {
        const write = ctx.db.run(`INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount, workspace_id, shadow, request_snapshot, end_user, end_user_verified, response_pending)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
            new Date().toISOString(),
            e.method,
            (0, utils_1.truncate)(ctx.redactor.text(e.path), constants_1.MAX_LOG_PATH_LENGTH),
            e.status,
            (0, utils_1.truncate)(ctx.redactor.text(e.userAgent), constants_1.MAX_LOG_UA_LENGTH),
            e.caller?.agentKeyName ?? null,
            e.actionId ?? null,
            e.caller?.ip ?? null,
            e.detail ? ctx.redactor.text(e.detail) : null,
            e.amount ?? null,
            e.workspaceId ?? constants_2.DEFAULT_WORKSPACE_ID,
            e.shadow ?? null,
            e.snapshot ?? null,
            e.caller?.endUser ?? null,
            verifiedFlag(e.caller),
            e.responsePending ? 1 : null,
        ]);
        try {
            const { lastID } = await (0, utils_1.withTimeout)(write, ctx.dbTimeoutMs, "audit log write");
            ctx.ledger.kick();
            return lastID;
        }
        catch (err) {
            // The request is about to be refused. If the timed-out row still lands later, it must
            // not claim the request was ALLOWED/QUEUED.
            if (err instanceof utils_1.DbTimeoutError && (e.status === "ALLOWED" || e.status === "QUEUED")) {
                write.then((r) => void correctLateRow(r.lastID, e), () => undefined);
            }
            throw err;
        }
    }
    /**
     * A timed-out ALLOWED/QUEUED row that landed late is corrected in place while it is still
     * unsealed; once the ledger has sealed it (rows are append-only from then on), a correcting
     * BLOCKED row is appended instead.
     */
    async function correctLateRow(id, e) {
        const note = "Refused (fail-closed): the audit write timed out, so the request was not forwarded.";
        try {
            // Nothing was forwarded, so no response is coming: clearing response_pending also lets the sealer go on.
            const r = await ctx.db.run("UPDATE agent_logs SET status = 'BLOCKED', detail = ?, response_pending = NULL WHERE id = ? AND row_hash IS NULL", [note, id]);
            if (r.changes === 0) {
                await ctx.db.run(`INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount, workspace_id, end_user, end_user_verified)
           VALUES (?, ?, ?, 'BLOCKED', ?, ?, ?, ?, ?, NULL, ?, ?, ?)`, [
                    new Date().toISOString(),
                    e.method,
                    (0, utils_1.truncate)(ctx.redactor.text(e.path), constants_1.MAX_LOG_PATH_LENGTH),
                    (0, utils_1.truncate)(ctx.redactor.text(e.userAgent), constants_1.MAX_LOG_UA_LENGTH),
                    e.caller?.agentKeyName ?? null,
                    e.actionId ?? null,
                    e.caller?.ip ?? null,
                    `Correction for log #${id}: ${note}`,
                    e.workspaceId ?? constants_2.DEFAULT_WORKSPACE_ID,
                    e.caller?.endUser ?? null,
                    verifiedFlag(e.caller),
                ]);
            }
            ctx.ledger.kick();
        }
        catch {
            // best effort
        }
    }
    async function logRefusal(e) {
        try {
            await logStrict(e);
        }
        catch (err) {
            console.error("Failed to write log for a refused request:", err);
        }
    }
    return { logStrict, logRefusal };
}
async function queuePending(ctx, audit, q) {
    const timed = (p, label) => (0, utils_1.withTimeout)(p, ctx.dbTimeoutMs, label);
    const r = ctx.redactor;
    const wsId = q.workspace.id;
    const pending = await timed(ctx.db.get("SELECT COUNT(*) as count FROM pending_actions WHERE status = 'PENDING'"), "approval queue count");
    if ((pending?.count ?? 0) >= constants_1.MAX_PENDING_ACTIONS) {
        await audit.logRefusal({ method: q.method, path: q.cleanPath, status: "BLOCKED", caller: q.caller, userAgent: q.caller.userAgent, detail: "approval queue full", workspaceId: wsId });
        return { ok: false, status: 503, error: "Service Unavailable", message: "The approval queue is full. Try again later.", retryAfter: 60 };
    }
    // Queued requests are stored until decided, so cap their size.
    if (q.originalBody !== null && Buffer.byteLength(q.originalBody) > constants_1.MAX_PENDING_BODY_BYTES) {
        await audit.logRefusal({ method: q.method, path: q.cleanPath, status: "BLOCKED", caller: q.caller, userAgent: q.caller.userAgent, detail: "approval body too large", workspaceId: wsId });
        return {
            ok: false,
            status: 413,
            error: "Payload Too Large",
            message: `Requests that need approval can have a body of at most ${constants_1.MAX_PENDING_BODY_BYTES / 1024} KB.`,
        };
    }
    const encryptedPayload = (0, crypto_1.encryptPayload)(JSON.stringify({ path: q.originalPath, body: q.originalBody }), ctx.config.replayEncryptionKey());
    const redactedBody = r.jsonText(q.originalBody);
    const displayBody = redactedBody !== null && redactedBody.length > constants_1.MAX_PENDING_DISPLAY_CHARS
        ? `${redactedBody.slice(0, constants_1.MAX_PENDING_DISPLAY_CHARS)}… [truncated]`
        : redactedBody;
    const query = r.json((0, utils_1.redactQueryObject)(q.query));
    // The agent's justification: an explicit header / _meta value, else a justification / reason /
    // summary field in the payload (HTTP body or MCP tool arguments).
    const justification = q.agentReason ?? (0, justification_1.justificationFromBodyText)(q.originalBody);
    const agentReason = justification ? r.text(justification) : null;
    const queuedAt = new Date().toISOString();
    const expiresAt = Date.now() + constants_1.PENDING_TTL_MS;
    const displayPath = (0, utils_1.truncate)(r.text((0, utils_1.redactQueryString)(q.originalPath)), constants_1.MAX_LOG_PATH_LENGTH);
    const userAgent = (0, utils_1.truncate)(r.text(q.caller.userAgent), constants_1.MAX_LOG_UA_LENGTH);
    const insert = ctx.db.run(`INSERT INTO pending_actions
       (timestamp, method, path, headers, body, status, expires_at, agent_key, encrypted_payload,
        query_json, caller_ip, caller_ua, agent_key_id, agent_key_prefix, agent_reason, matched_policy, kind, owner, workspace_id, end_user, end_user_verified)
     VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
        queuedAt,
        q.method,
        displayPath,
        JSON.stringify(r.headers(q.headers)),
        displayBody,
        expiresAt,
        q.caller.agentKeyName,
        encryptedPayload,
        JSON.stringify(query),
        q.caller.ip,
        userAgent,
        q.caller.agentKeyId,
        q.caller.agentKeyPrefix,
        agentReason,
        q.matched,
        q.kind,
        q.kind === "mcp" ? ctx.instanceId : null,
        wsId,
        q.caller.endUser ?? null,
        verifiedFlag(q.caller),
    ]);
    // If the insert outlives the timeout, or anything after it fails, the agent is told the
    // request failed, so the queued row must never be approvable: expire it when it lands.
    const discard = (id) => {
        void ctx.db
            .run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'", ["Discarded: the gateway failed while queueing this request and told the agent it was refused.", id])
            .catch((err) => console.error("Could not discard a half-queued action:", err));
    };
    let inserted;
    try {
        inserted = await timed(insert, "approval queue insert");
    }
    catch (err) {
        if (err instanceof utils_1.DbTimeoutError)
            insert.then((res) => discard(res.lastID), () => undefined);
        throw err;
    }
    try {
        await audit.logStrict({
            method: q.method,
            path: q.cleanPath,
            status: "QUEUED",
            caller: q.caller,
            userAgent: q.caller.userAgent,
            actionId: inserted.lastID,
            detail: q.kind === "mcp" ? `mcp ${q.matched}` : q.matched,
            amount: q.amount ?? null,
            workspaceId: wsId,
            snapshot: q.snapshot ?? null,
        });
    }
    catch (err) {
        discard(inserted.lastID);
        throw err;
    }
    // Phone / chat notifications. Fire-and-forget: they can never change the outcome.
    void ctx.notifier.notifyPending({
        id: inserted.lastID,
        queuedAt,
        expiresAt,
        method: q.method,
        path: displayPath,
        body: displayBody,
        query,
        callerIp: q.caller.ip,
        callerUa: userAgent,
        agentKey: q.caller.agentKeyName,
        agentKeyPrefix: q.caller.agentKeyPrefix,
        agentReason,
        matchedPolicy: q.matched,
        workspace: (0, notify_1.workspaceNotice)(q.workspace),
    });
    return { ok: true, id: inserted.lastID, queuedAt, expiresAt };
}
/** Marks an action that is no longer queued-for-real (agent gone, error after insert) as EXPIRED. */
function discardPending(ctx, id, reason) {
    return ctx.db
        .run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'", [reason, id])
        .then(() => undefined);
}
