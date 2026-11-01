"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerLogRoutes = registerLogRoutes;
const utils_1 = require("../utils");
// window -> total span and bucket size (both in ms)
const WINDOWS = {
    "1h": { spanMs: 60 * 60000, stepMs: 5 * 60000 },
    "2h": { spanMs: 2 * 60 * 60000, stepMs: 10 * 60000 },
    "24h": { spanMs: 24 * 60 * 60000, stepMs: 60 * 60000 },
    "1w": { spanMs: 7 * 24 * 60 * 60000, stepMs: 24 * 60 * 60000 },
};
const LOG_STATUSES = ["ALLOWED", "BLOCKED", "QUEUED", "RATE_LIMITED", "APPROVED", "REJECTED"];
/** Audit log listing and traffic analytics. */
function registerLogRoutes(router, ctx) {
    const { db, license } = ctx;
    router.get("/logs", async (req, res) => {
        try {
            const { status, method, search, from, to, limit } = req.query;
            let sql = "SELECT * FROM agent_logs WHERE 1=1";
            const params = [];
            if (typeof status === "string" && status.trim() !== "") {
                sql += " AND status = ?";
                params.push(status.trim().toUpperCase());
            }
            if (typeof method === "string" && method.trim() !== "") {
                sql += " AND method = ?";
                params.push(method.trim().toUpperCase());
            }
            if (typeof search === "string" && search.trim() !== "") {
                sql += " AND path LIKE ? ESCAPE '\\'";
                params.push(`%${(0, utils_1.escapeLike)(search.trim().slice(0, 200))}%`);
            }
            if (typeof from === "string" && from.trim() !== "") {
                const fromDate = new Date(from.trim());
                if (!Number.isNaN(fromDate.getTime())) {
                    sql += " AND timestamp >= ?";
                    params.push(fromDate.toISOString());
                }
            }
            if (typeof to === "string" && to.trim() !== "") {
                const toDate = new Date(to.trim());
                if (!Number.isNaN(toDate.getTime())) {
                    sql += " AND timestamp <= ?";
                    params.push(toDate.toISOString());
                }
            }
            const parsedLimit = Math.min(Math.max(Math.trunc(Number(limit)) || 100, 1), 1000);
            sql += " ORDER BY id DESC LIMIT ?";
            params.push(parsedLimit);
            res.json(await db.all(sql, params));
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Logs error", err, "Could not load audit logs.");
        }
    });
    // Traffic analytics. Rows are bucketed in SQL by integer-dividing the unix time
    // by the bucket size, so the buckets line up exactly with the ones built below.
    router.get("/logs/analytics", async (req, res) => {
        try {
            const requested = typeof req.query.window === "string" ? req.query.window.toLowerCase() : "24h";
            // The 7-day window is Pro. Community falls back to 24h and says so, rather than failing.
            const proRequired = requested === "1w" && !(await license.isPro());
            const windowParam = proRequired ? "24h" : requested;
            const { spanMs, stepMs } = WINDOWS[windowParam] ?? WINDOWS["24h"];
            const bucketCount = spanMs / stepMs;
            const stepSec = stepMs / 1000;
            const lastBucket = Math.floor(Date.now() / stepMs);
            const firstBucket = lastBucket - bucketCount + 1;
            const cutoffIso = new Date(firstBucket * stepMs).toISOString();
            // 1. Get resolved/direct traffic from agent_logs (excluding raw arrival QUEUED logs)
            const rows = await db.all(`SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket, status, COUNT(*) AS count
         FROM agent_logs
         WHERE timestamp >= ? AND status != 'QUEUED'
         GROUP BY bucket, status`, [stepSec, cutoffIso]);
            // 2. Get ONLY currently pending requests bucketed by when they were queued
            const pendingBuckets = await db.all(`SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket, COUNT(*) AS count
         FROM pending_actions
         WHERE status = 'PENDING' AND timestamp >= ?
         GROUP BY bucket`, [stepSec, cutoffIso]);
            // 3. Get total live pending count for the top KPI card
            const pendingCountRow = await db.get(`SELECT COUNT(*) as count FROM pending_actions WHERE status = 'PENDING'`);
            const actualPendingCount = pendingCountRow?.count ?? 0;
            // 4. Top Targeted Endpoints (combines resolved logs + currently pending actions)
            const topEndpoints = await db.all(`SELECT
           method,
           path,
           COUNT(*) AS total,
           SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN 1 ELSE 0 END) AS allowed,
           SUM(CASE WHEN status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED', 'PENDING') THEN 1 ELSE 0 END) AS intervened
         FROM (
           SELECT method, path, status FROM agent_logs WHERE timestamp >= ? AND status != 'QUEUED'
           UNION ALL
           SELECT method, path, status FROM pending_actions WHERE status = 'PENDING' AND timestamp >= ?
         )
         GROUP BY method, path
         ORDER BY total DESC, intervened DESC
         LIMIT 8`, [cutoffIso, cutoffIso]);
            // 5. Top Active AI Agents / Callers
            const topAgents = await db.all(`SELECT
           COALESCE(NULLIF(TRIM(user_agent), ''), 'Unknown Agent') AS agent,
           COUNT(*) AS total,
           SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN 1 ELSE 0 END) AS allowed,
           SUM(CASE WHEN status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED') THEN 1 ELSE 0 END) AS intervened
         FROM agent_logs
         WHERE timestamp >= ? AND status != 'QUEUED'
         GROUP BY agent
         ORDER BY total DESC, intervened DESC
         LIMIT 8`, [cutoffIso]);
            const buckets = new Map();
            for (let b = firstBucket; b <= lastBucket; b++) {
                buckets.set(b, {
                    hour: new Date(b * stepMs).toISOString(),
                    ALLOWED: 0,
                    BLOCKED: 0,
                    QUEUED: 0,
                    RATE_LIMITED: 0,
                    APPROVED: 0,
                    REJECTED: 0,
                    total: 0,
                });
            }
            const totals = {
                ALLOWED: 0,
                BLOCKED: 0,
                QUEUED: actualPendingCount,
                RATE_LIMITED: 0,
                APPROVED: 0,
                REJECTED: 0,
            };
            for (const r of rows) {
                if (!LOG_STATUSES.includes(r.status))
                    continue;
                totals[r.status] += r.count;
                const bucket = buckets.get(r.bucket);
                if (bucket) {
                    bucket[r.status] += r.count;
                    bucket.total += r.count;
                }
            }
            for (const p of pendingBuckets) {
                const bucket = buckets.get(p.bucket);
                if (bucket) {
                    bucket.QUEUED += p.count;
                    bucket.total += p.count;
                }
            }
            res.json({
                window: WINDOWS[windowParam] ? windowParam : "24h",
                ...(proRequired ? { proRequired: true, requestedWindow: requested } : {}),
                statusTotals: LOG_STATUSES.map((status) => ({ status, count: totals[status] })).filter((t) => t.count > 0 || (t.status === "QUEUED" && actualPendingCount > 0)),
                hourly: Array.from(buckets.values()),
                topEndpoints,
                topAgents,
            });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Analytics error", err, "Could not load analytics.");
        }
    });
}
