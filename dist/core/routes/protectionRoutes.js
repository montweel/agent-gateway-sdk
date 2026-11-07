"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.modeLabel = void 0;
exports.csvCell = csvCell;
exports.registerProtectionRoutes = registerProtectionRoutes;
const operatingMode_1 = require("../operatingMode");
const protection_1 = require("../protection");
Object.defineProperty(exports, "modeLabel", { enumerable: true, get: function () { return protection_1.modeLabel; } });
const utils_1 = require("../utils");
const scope_1 = require("./scope");
/**
 * Shop-owner endpoints (all honour the x-mont-workspace scope):
 *   GET  /protection/summary?hours=24   money protected, counts, budgets, emergency mode, shadow counts
 *   GET  /emergency                     current emergency mode (the workspace's own when one is selected)
 *   POST /emergency                     { mode: "normal" | "approval_only" | "lockdown", reason? }   (admin)
 *                                       global switch when no / the default workspace is selected,
 *                                       otherwise that client's switch
 *   GET  /guards/usage                  live spending-budget usage
 *   GET  /logs/export.csv               audit log as CSV (same filters as /logs, up to 50,000 rows)
 *   POST /alerts/digest                 send the daily digest now (admin)
 */
// v1.3 columns first (spreadsheets / scripts built on them keep working), v2 columns appended.
const CSV_COLUMNS = [
    "id",
    "timestamp",
    "method",
    "path",
    "status",
    "amount",
    "agent_key",
    "caller_ip",
    "user_agent",
    "action_id",
    "detail",
    "workspace",
    "shadow",
    "row_hash",
];
function csvCell(v) {
    let s = v === null || v === undefined ? "" : String(v);
    s = s.replace(/\r?\n/g, " ");
    // Spreadsheet formula injection: agent-controlled text must never execute in Excel / Sheets.
    if (/^[=+\-@\t\r]/.test(s))
        s = `'${s}`;
    return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function registerProtectionRoutes(router, ctx) {
    router.get("/protection/summary", async (req, res) => {
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        try {
            const hours = Math.min(Math.max(Math.trunc(Number(req.query.hours)) || 24, 1), 24 * 31);
            res.json(await (0, protection_1.buildSummary)(ctx, hours, scoped?.id ?? null));
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Protection summary error", err, "Could not build the protection summary.");
        }
    });
    router.get("/emergency", (req, res) => {
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        if (scoped && !scoped.isDefault) {
            res.json({ mode: scoped.mode, reason: scoped.modeReason, changedBy: scoped.modeChangedBy, changedAt: scoped.modeChangedAt, workspace: scoped.slug, global: ctx.emergency.current() });
            return;
        }
        res.json(ctx.emergency.current());
    });
    router.post("/emergency", async (req, res) => {
        if (req.user?.role !== "admin") {
            (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can change the emergency mode.");
            return;
        }
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        const body = (req.body ?? {});
        if (typeof body.mode !== "string" || !operatingMode_1.EMERGENCY_MODES.includes(body.mode)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", `mode must be one of ${operatingMode_1.EMERGENCY_MODES.join(", ")}.`);
            return;
        }
        if (body.reason !== undefined && body.reason !== null && (typeof body.reason !== "string" || body.reason.length > 300)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "reason must be a string of at most 300 characters.");
            return;
        }
        const reason = typeof body.reason === "string" ? body.reason : null;
        try {
            if (scoped && !scoped.isDefault) {
                const ws = await ctx.workspaces.setMode(scoped.id, body.mode, reason, (0, scope_1.actorOf)(req));
                res.json({ success: true, mode: ws.mode, reason: ws.modeReason, changedBy: ws.modeChangedBy, changedAt: ws.modeChangedAt, workspace: ws.slug });
                return;
            }
            const state = await ctx.emergency.set(body.mode, reason, (0, scope_1.actorOf)(req));
            res.json({ success: true, ...state });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Emergency mode error", err, "Could not change the emergency mode.");
        }
    });
    router.get("/guards/usage", async (req, res) => {
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        try {
            res.json(await ctx.guards.usage(scoped?.id ?? null));
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Budget usage error", err, "Could not load budget usage.");
        }
    });
    router.get("/logs/export.csv", async (req, res) => {
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        try {
            const { status, method, from, to } = req.query;
            const wf = (0, protection_1.workspaceFilter)(scoped?.id ?? null);
            let sql = `SELECT id, timestamp, workspace_id, method, path, status, shadow, amount, agent_key, caller_ip, user_agent, action_id, detail, row_hash
                 FROM agent_logs WHERE 1=1${wf.sql}`;
            const params = [...wf.params];
            if (typeof status === "string" && status.trim()) {
                sql += " AND status = ?";
                params.push(status.trim().toUpperCase());
            }
            if (typeof method === "string" && method.trim()) {
                sql += " AND method = ?";
                params.push(method.trim().toUpperCase());
            }
            for (const [v, op] of [
                [from, ">="],
                [to, "<="],
            ]) {
                if (typeof v === "string" && v.trim()) {
                    const d = new Date(v.trim());
                    if (!Number.isNaN(d.getTime())) {
                        sql += ` AND timestamp ${op} ?`;
                        params.push(d.toISOString());
                    }
                }
            }
            sql += " ORDER BY id DESC LIMIT 50000";
            const rows = await ctx.db.all(sql, params);
            const lines = [
                CSV_COLUMNS.join(","),
                ...rows.map((r) => {
                    const withWs = { ...r, workspace: ctx.workspaces.get(r.workspace_id ?? 1)?.slug ?? r.workspace_id };
                    return CSV_COLUMNS.map((c) => csvCell(withWs[c])).join(",");
                }),
            ];
            res.setHeader("Content-Type", "text/csv; charset=utf-8");
            res.setHeader("Content-Disposition", `attachment; filename="mont-audit${scoped ? `-${scoped.slug}` : ""}-${new Date().toISOString().slice(0, 10)}.csv"`);
            res.send(`﻿${lines.join("\n")}\n`);
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "CSV export error", err, "Could not export the audit log.");
        }
    });
    router.post("/alerts/digest", async (req, res) => {
        if (req.user?.role !== "admin") {
            (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can send the digest.");
            return;
        }
        try {
            const results = await ctx.alerts.sendDigest();
            if (results.length === 0) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "No notification channel is enabled and fully configured.");
                return;
            }
            res.json({ success: results.every((r) => r.ok), results });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Digest error", err, "Could not send the digest.");
        }
    });
}
