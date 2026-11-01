"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerApprovalRoutes = registerApprovalRoutes;
const constants_1 = require("../constants");
const crypto_1 = require("../crypto");
const proxy_1 = require("../proxy");
const utils_1 = require("../utils");
const MASKED = "[hidden for viewers]";
/**
 * Pending approvals.
 *
 * State machine:
 *   PENDING --approve--> EXECUTING --ok--> APPROVED
 *                              \--error--> FAILED --retry--> EXECUTING
 *   PENDING|FAILED --reject--> REJECTED
 *   PENDING|FAILED --24h----> EXPIRED
 * EXECUTING is claimed with a conditional UPDATE, so two admins clicking at
 * once can never replay the same action twice.
 */
function registerApprovalRoutes(router, ctx) {
    const { db, config: configStore, rules, port, replaySecret } = ctx;
    async function expireStale() {
        await db.run(`UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL
       WHERE status IN ('PENDING', 'FAILED') AND expires_at IS NOT NULL AND expires_at <= ?`, [Date.now()]);
    }
    router.get("/approvals", async (req, res) => {
        try {
            await expireStale();
            // Explicit columns: encrypted_payload must never leave the server.
            const rows = await db.all(`SELECT id, timestamp, method, path, headers, body, status, response_preview, decided_by, expires_at, agent_key
         FROM pending_actions ORDER BY id DESC LIMIT 100`);
            // Request bodies and upstream responses can contain customer data: viewers see that they exist, not what they hold.
            if (req.user?.role === "viewer") {
                res.json(rows.map((r) => ({
                    ...r,
                    body: r.body === null ? null : MASKED,
                    response_preview: r.response_preview === null ? null : MASKED,
                })));
                return;
            }
            res.json(rows);
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Approvals error", err, "Could not load approvals.");
        }
    });
    /** Replays a claimed (EXECUTING) action and records the outcome. */
    async function execute(row, actorName, res) {
        const id = row.id;
        const config = configStore.load();
        const replayToSelf = config.targetUrl === "";
        const baseUrl = replayToSelf ? `http://127.0.0.1:${port}` : config.targetUrl;
        const saved = (0, utils_1.parseJsonObject)(row.headers);
        const replayHeaders = {};
        if (saved["content-type"])
            replayHeaders["content-type"] = saved["content-type"];
        if (saved["accept"])
            replayHeaders["accept"] = saved["accept"];
        if (saved["user-agent"])
            replayHeaders["user-agent"] = saved["user-agent"];
        // The real request (secrets included) is decrypted here, in memory, for this
        // one call. Rows queued before encryption existed only have the redacted copy.
        let requestPath = row.path;
        let requestBody = row.body;
        let usedRedactedCopy = row.encrypted_payload === null;
        if (row.encrypted_payload !== null) {
            try {
                const original = JSON.parse((0, crypto_1.decryptPayload)(row.encrypted_payload, configStore.replayEncryptionKey()));
                if (typeof original.path !== "string")
                    throw new Error("Payload has no path.");
                requestPath = original.path;
                requestBody = typeof original.body === "string" ? original.body : null;
                usedRedactedCopy = false;
            }
            catch (err) {
                console.error(`Could not decrypt the stored request for action ${id}:`, err);
                await db
                    .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ? WHERE id = ?", [
                    "The stored request could not be decrypted (was config.json's replayEncryptionKey changed?). Reject it and ask the agent to send it again.",
                    id,
                ])
                    .catch(() => undefined);
                (0, utils_1.sendError)(res, 500, "Internal Server Error", "The stored request could not be decrypted. Reject it and have the agent send it again.", { id, status: "FAILED" });
                return;
            }
        }
        const hasBody = requestBody !== null && !constants_1.NO_BODY_METHODS.includes(row.method);
        if (hasBody && !replayHeaders["content-type"])
            replayHeaders["content-type"] = "application/json";
        if (replayToSelf)
            replayHeaders[constants_1.REPLAY_HEADER] = replaySecret;
        const warning = usedRedactedCopy && (row.body?.includes(constants_1.REDACTED) || row.path.includes(encodeURIComponent(constants_1.REDACTED)))
            ? "This request was queued before encrypted replay existed, so its sensitive fields were replayed as " +
                `"${constants_1.REDACTED}".`
            : undefined;
        try {
            const upstream = await fetch(baseUrl + requestPath, {
                method: row.method,
                headers: replayHeaders,
                body: hasBody ? requestBody : undefined,
                redirect: "manual",
                signal: AbortSignal.timeout(constants_1.UPSTREAM_TIMEOUT_MS),
            });
            const text = (await (0, proxy_1.readCapped)(upstream)).toString("utf-8");
            const preview = `${upstream.status} ${text.slice(0, 500)}`;
            // Done: the secrets are no longer needed, so wipe them for good.
            await db.run("UPDATE pending_actions SET status = 'APPROVED', response_preview = ?, encrypted_payload = NULL WHERE id = ?", [preview, id]);
            await db.run("INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key) VALUES (?, ?, ?, 'APPROVED', ?, ?)", [new Date().toISOString(), row.method, row.path, `decided_by:${actorName}`, row.agent_key ?? null]);
            res.json({
                success: true,
                id,
                status: "APPROVED",
                decided_by: actorName,
                replayStatus: upstream.status,
                response_preview: preview,
                ...(warning ? { warning } : {}),
            });
        }
        catch (err) {
            // Not put back in the queue: the target may have received the request
            // before the failure, so a human must choose to RETRY.
            const timedOut = (0, proxy_1.isTimeoutError)(err);
            const reason = timedOut ? "the target did not respond in time" : "the target could not be reached";
            console.error("Replay failed:", err);
            await db
                .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ? WHERE id = ?", [
                `Replay failed: ${reason}.`,
                id,
            ])
                .catch(() => undefined);
            (0, utils_1.sendError)(res, timedOut ? 504 : 502, timedOut ? "Gateway Timeout" : "Bad Gateway", `Replay failed (${reason}). The action is marked FAILED; an admin can retry it.`, { id, status: "FAILED" });
        }
    }
    router.post("/approvals/:id/decide", async (req, res) => {
        try {
            const id = Number(req.params.id);
            if (!Number.isInteger(id) || id < 1) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Approval id must be a positive whole number.");
                return;
            }
            const rawDecision = req.body?.decision;
            const normalized = typeof rawDecision === "string" ? rawDecision.trim().toUpperCase() : "";
            let decision;
            if (normalized === "APPROVE" || normalized === "APPROVED")
                decision = "APPROVE";
            else if (normalized === "REJECT" || normalized === "REJECTED")
                decision = "REJECT";
            else if (normalized === "RETRY")
                decision = "RETRY";
            else {
                (0, utils_1.sendError)(res, 400, "Bad Request", 'decision must be "APPROVE", "REJECT" or "RETRY".');
                return;
            }
            // Defence in depth: the auth middleware already refuses non-GET calls from viewers.
            if (req.user?.role !== "admin") {
                (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can decide approvals.");
                return;
            }
            await expireStale();
            const row = await db.get("SELECT * FROM pending_actions WHERE id = ?", [id]);
            if (!row) {
                (0, utils_1.sendError)(res, 404, "Not Found", `No pending action with id ${id}.`);
                return;
            }
            if (row.status === "EXPIRED") {
                (0, utils_1.sendError)(res, 410, "Gone", `Action ${id} expired before it was decided. The agent must send it again.`);
                return;
            }
            const actorName = req.user ? (req.user.sso ? `sso:${req.user.username}` : req.user.username) : "admin";
            // ---- Reject (a PENDING or FAILED action) ----
            if (decision === "REJECT") {
                if (row.status !== "PENDING" && row.status !== "FAILED") {
                    (0, utils_1.sendError)(res, 409, "Conflict", `Action ${id} is ${row.status} and can no longer be rejected.`);
                    return;
                }
                const result = await db.run("UPDATE pending_actions SET status = 'REJECTED', decided_by = ?, encrypted_payload = NULL WHERE id = ? AND status = ?", [actorName, id, row.status]);
                if (result.changes === 0) {
                    (0, utils_1.sendError)(res, 409, "Conflict", `Action ${id} was already decided.`);
                    return;
                }
                await db.run("INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key) VALUES (?, ?, ?, 'REJECTED', ?, ?)", [new Date().toISOString(), row.method, row.path, `decided_by:${actorName}`, row.agent_key ?? null]);
                res.json({ success: true, id, status: "REJECTED", decided_by: actorName });
                return;
            }
            // ---- Approve (PENDING) or Retry (FAILED) ----
            const from = decision === "APPROVE" ? "PENDING" : "FAILED";
            if (row.status !== from) {
                (0, utils_1.sendError)(res, 409, "Conflict", decision === "APPROVE"
                    ? `Action ${id} is ${row.status}; only PENDING actions can be approved.`
                    : `Action ${id} is ${row.status}; only FAILED actions can be retried.`);
                return;
            }
            // The rule may have changed while the request waited. Re-check it now.
            const rulePath = (0, utils_1.normalizePath)(row.path.split("?")[0]);
            const rule = rules.lookup(row.method, rulePath);
            if (!rule || rule.mode === "BLOCK") {
                (0, utils_1.sendError)(res, 409, "Conflict", rule
                    ? `The rule for ${row.method} ${rulePath} is now BLOCK, so this action cannot run. Reject it instead.`
                    : `${row.method} ${rulePath} no longer has a rule (default deny), so this action cannot run. Reject it instead.`);
                return;
            }
            const claim = await db.run(`UPDATE pending_actions SET status = 'EXECUTING', decided_by = ?
         WHERE id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)`, [actorName, id, from, Date.now()]);
            if (claim.changes === 0) {
                (0, utils_1.sendError)(res, 409, "Conflict", `Action ${id} was already decided or has expired.`);
                return;
            }
            await execute(row, actorName, res);
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Decide error", err, "Could not record the decision.");
        }
    });
}
