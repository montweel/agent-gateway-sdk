"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.csvCell = csvCell;
exports.registerProtectionRoutes = registerProtectionRoutes;
const operatingMode_1 = require("../operatingMode");
const protection_1 = require("../protection");
const utils_1 = require("../utils");
/**
 * Shop-owner endpoints:
 *   GET  /protection/summary?hours=24   money protected, counts, budgets, emergency mode
 *   GET  /emergency                     current emergency mode
 *   POST /emergency                     { mode: "normal" | "approval_only" | "lockdown", reason? }   (admin)
 *   GET  /guards/usage                  live spending-budget usage
 *   GET  /logs/export.csv               audit log as CSV (same filters as /logs, up to 50,000 rows)
 *   POST /alerts/digest                 send the daily digest now (admin)
 */
const CSV_COLUMNS = ["id", "timestamp", "method", "path", "status", "amount", "agent_key", "caller_ip", "user_agent", "action_id", "detail"];
function csvCell(v) {
    let s = v === null || v === undefined ? "" : String(v);
    s = s.replace(/\r?\n/g, " ");
    // Spreadsheet formula injection: agent-controlled text must never execute in Excel / Sheets.
    if (/^[=+\-@\t\r]/.test(s))
        s = `'${s}`;
    return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function registerProtectionRoutes(router, ctx) {
    const actorOf = (req) => (req.user ? (req.user.sso ? `sso:${req.user.username}` : req.user.username) : "admin");
    router.get("/protection/summary", async (req, res) => {
        try {
            const hours = Math.min(Math.max(Math.trunc(Number(req.query.hours)) || 24, 1), 24 * 31);
            res.json(await (0, protection_1.buildSummary)(ctx, hours));
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Protection summary error", err, "Could not build the protection summary.");
        }
    });
    router.get("/emergency", (_req, res) => {
        res.json(ctx.emergency.current());
    });
    router.post("/emergency", async (req, res) => {
        if (req.user?.role !== "admin") {
            (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can change the emergency mode.");
            return;
        }
        const body = (req.body ?? {});
        if (typeof body.mode !== "string" || !operatingMode_1.EMERGENCY_MODES.includes(body.mode)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", `mode must be one of ${operatingMode_1.EMERGENCY_MODES.join(", ")}.`);
            return;
        }
        if (body.reason !== undefined && body.reason !== null && (typeof body.reason !== "string" || body.reason.length > 300)) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "reason must be a string of at most 300 characters.");
            return;
        }
        try {
            const state = await ctx.emergency.set(body.mode, typeof body.reason === "string" ? body.reason : null, actorOf(req));
            res.json({ success: true, ...state });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Emergency mode error", err, "Could not change the emergency mode.");
        }
    });
    router.get("/guards/usage", async (_req, res) => {
        try {
            res.json(await ctx.guards.usage());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Budget usage error", err, "Could not load budget usage.");
        }
    });
    router.get("/logs/export.csv", async (req, res) => {
        try {
            const { status, method, from, to } = req.query;
            let sql = `SELECT ${CSV_COLUMNS.join(", ")} FROM agent_logs WHERE 1=1`;
            const params = [];
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
            const lines = [CSV_COLUMNS.join(","), ...rows.map((r) => CSV_COLUMNS.map((c) => csvCell(r[c])).join(","))];
            res.setHeader("Content-Type", "text/csv; charset=utf-8");
            res.setHeader("Content-Disposition", `attachment; filename="mont-audit-${new Date().toISOString().slice(0, 10)}.csv"`);
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
