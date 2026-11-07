"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerApprovalRoutes = registerApprovalRoutes;
const utils_1 = require("../utils");
const protection_1 = require("../protection");
const scope_1 = require("./scope");
const MASKED = "[hidden for viewers]";
function parseId(raw) {
    const id = Number(raw);
    return Number.isInteger(id) && id >= 1 ? id : null;
}
/** Pending approvals, post-approval revocation and the kill-switch list. Logic lives in approvals.ts. */
function registerApprovalRoutes(router, ctx) {
    const { db, approvals, blocklist } = ctx;
    router.get("/approvals", async (req, res) => {
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        try {
            await approvals.expireStale();
            const wf = (0, protection_1.workspaceFilter)(scoped?.id ?? null);
            // Explicit columns: encrypted_payload / patch_encrypted must never leave the server.
            const rows = await db.all(`SELECT id, timestamp, method, path, headers, body, status, response_preview, decided_by, expires_at, agent_key,
                query_json, caller_ip, caller_ua, agent_key_id, agent_key_prefix, agent_reason, matched_policy,
                revoked_at, revoked_by, rollback_status, kind, workspace_id, modified_body, modified_query
         FROM pending_actions WHERE 1=1${wf.sql} ORDER BY id DESC LIMIT 100`, wf.params);
            const withWorkspace = rows.map((r) => {
                const ws = ctx.workspaces.get(r.workspace_id ?? 1);
                return { ...r, workspace_slug: ws?.slug ?? null, workspace_name: ws?.name ?? null };
            });
            // Request bodies, query strings, agent justifications and upstream responses can contain
            // customer data: viewers see that they exist, not what they hold.
            if (req.user?.role === "viewer") {
                res.json(withWorkspace.map((r) => ({
                    ...r,
                    body: r.body === null ? null : MASKED,
                    query_json: r.query_json === null ? null : JSON.stringify({ hidden: MASKED }),
                    agent_reason: r.agent_reason === null ? null : MASKED,
                    response_preview: r.response_preview === null ? null : MASKED,
                    modified_body: r.modified_body === null ? null : MASKED,
                    modified_query: r.modified_query === null ? null : JSON.stringify({ hidden: MASKED }),
                })));
                return;
            }
            res.json(withWorkspace);
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Approvals error", err, "Could not load approvals.");
        }
    });
    router.post("/approvals/:id/decide", async (req, res) => {
        try {
            const id = parseId(req.params.id);
            if (id === null) {
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
            // "Edit & Approve": { decision: "APPROVE", modifiedBody?: <JSON>, modifiedQuery?: { name: "value" } }
            const b = (req.body ?? {});
            const edits = b.modifiedBody !== undefined || b.modifiedQuery !== undefined ? { body: b.modifiedBody, query: b.modifiedQuery } : undefined;
            const result = await approvals.decide(id, decision, (0, scope_1.actorOf)(req), edits);
            res.status(result.status).json(result.body);
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Decide error", err, "Could not record the decision.");
        }
    });
    /**
     * Revoke & Block Caller. Body (all optional):
     *   { blockAgentKey: true, blockIp: true, fireRollback: true, reason: "..." }
     */
    router.post("/approvals/:id/revoke", async (req, res) => {
        try {
            const id = parseId(req.params.id);
            if (id === null) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "Action id must be a positive whole number.");
                return;
            }
            if (req.user?.role !== "admin") {
                (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can revoke approvals.");
                return;
            }
            const b = (req.body ?? {});
            for (const k of ["blockAgentKey", "blockIp", "fireRollback"]) {
                if (b[k] !== undefined && typeof b[k] !== "boolean") {
                    (0, utils_1.sendError)(res, 400, "Bad Request", `${k} must be true or false.`);
                    return;
                }
            }
            if (b.reason !== undefined && b.reason !== null && (typeof b.reason !== "string" || b.reason.length > 500)) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "reason must be a string of at most 500 characters.");
                return;
            }
            const result = await approvals.revoke(id, {
                blockAgentKey: b.blockAgentKey !== false,
                blockIp: b.blockIp !== false,
                fireRollback: b.fireRollback !== false,
                reason: typeof b.reason === "string" && b.reason.trim() ? b.reason.trim() : null,
            }, (0, scope_1.actorOf)(req));
            res.status(result.status).json(result.body);
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Revoke error", err, "Could not revoke the action.");
        }
    });
    router.get("/blocked-callers", async (_req, res) => {
        try {
            res.json(await blocklist.list());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Blocked callers error", err, "Could not load blocked callers.");
        }
    });
    router.delete("/blocked-callers/:id", async (req, res) => {
        try {
            const id = parseId(req.params.id);
            if (id === null) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "id must be a positive whole number.");
                return;
            }
            if (req.user?.role !== "admin") {
                (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can unblock callers.");
                return;
            }
            const removed = await blocklist.remove(id);
            if (!removed) {
                (0, utils_1.sendError)(res, 404, "Not Found", `No blocked caller with id ${id}.`);
                return;
            }
            res.json({ success: true, id });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Unblock error", err, "Could not unblock the caller.");
        }
    });
}
