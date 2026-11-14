import type { NextFunction, Request, Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { LogStatus } from "../types";
import { escapeLike, sendError, sendInternalError } from "../utils";
import { workspaceFilter } from "../protection";
import { readScope } from "./scope";

// window -> total span and bucket size (both in ms)
const WINDOWS: Record<string, { spanMs: number; stepMs: number }> = {
  "1h": { spanMs: 60 * 60_000, stepMs: 5 * 60_000 },
  "2h": { spanMs: 2 * 60 * 60_000, stepMs: 10 * 60_000 },
  "24h": { spanMs: 24 * 60 * 60_000, stepMs: 60 * 60_000 },
  "1w": { spanMs: 7 * 24 * 60 * 60_000, stepMs: 24 * 60 * 60_000 },
};

const LOG_STATUSES: LogStatus[] = ["ALLOWED", "BLOCKED", "QUEUED", "RATE_LIMITED", "APPROVED", "REJECTED", "RESPONSE_BLOCKED", "RESPONSE_SCRUBBED"];

interface AnalyticsBucket {
  hour: string;
  ALLOWED: number;
  BLOCKED: number;
  QUEUED: number;
  RATE_LIMITED: number;
  APPROVED: number;
  REJECTED: number;
  RESPONSE_BLOCKED: number;
  RESPONSE_SCRUBBED: number;
  total: number;
}

/** How the analytics "top agents" table labels a row with no user agent; the user_agent filter accepts it too. */
export const UNKNOWN_AGENT_LABEL = "Unknown Agent";
const AGENT_LABEL_SQL = `COALESCE(NULLIF(TRIM(user_agent), ''), '${UNKNOWN_AGENT_LABEL}')`;

/**
 * Audit log filters shared by GET /logs and GET /logs/export.csv, so the CSV always holds
 * exactly the rows the dashboard shows. Returns SQL starting with " AND ..." (or empty).
 *   status, method          exact (case-insensitive)
 *   search                  path contains
 *   path                    path equals (e.g. from an analytics row)
 *   action_id               the approval / request id (#736 in Telegram and Pending Approvals)
 *   user_agent              exact, as labelled in analytics (UNKNOWN_AGENT_LABEL = none recorded)
 *   from, to                ISO timestamps
 *   shadow=1                only shadow-mode hits
 *   unknown=1               only calls that matched no rule (default deny)
 */
export function logFilterSql(query: Request["query"]): { sql: string; params: unknown[] } {
  const { status, method, search, path, action_id, user_agent, from, to, shadow, unknown } = query;
  let sql = "";
  const params: unknown[] = [];
  const text = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : null);

  if (shadow === "1" || shadow === "true") sql += " AND shadow IS NOT NULL";
  // Unknown endpoints: calls that matched no rule and were refused by default deny
  // (see interceptor.ts and toolGuard.ts, which write exactly these details).
  if (unknown === "1" || unknown === "true") sql += " AND status = 'BLOCKED' AND detail IN ('default-deny', 'mcp default-deny')";
  if (text(status)) {
    sql += " AND status = ?";
    params.push(text(status)!.toUpperCase());
  }
  if (text(method)) {
    sql += " AND method = ?";
    params.push(text(method)!.toUpperCase());
  }
  if (text(search)) {
    sql += " AND path LIKE ? ESCAPE '\\'";
    params.push(`%${escapeLike(text(search)!.slice(0, 200))}%`);
  }
  if (text(path)) {
    sql += " AND path = ?";
    params.push(text(path)!.slice(0, 2048));
  }
  if (text(action_id)) {
    // A non-numeric id can match nothing, rather than being ignored and showing everything.
    const id = Number(text(action_id)!.replace(/^#/, ""));
    sql += " AND action_id = ?";
    params.push(Number.isInteger(id) && id > 0 ? id : -1);
  }
  if (text(user_agent)) {
    sql += ` AND ${AGENT_LABEL_SQL} = ?`;
    params.push(text(user_agent)!.slice(0, 1024));
  }
  for (const [v, op] of [
    [from, ">="],
    [to, "<="],
  ] as const) {
    if (text(v)) {
      const d = new Date(text(v)!);
      if (!Number.isNaN(d.getTime())) {
        sql += ` AND timestamp ${op} ?`;
        params.push(d.toISOString());
      }
    }
  }
  return { sql, params };
}

/** Audit log listing and traffic analytics. */
export function registerLogRoutes(router: Router, ctx: GatewayContext): void {
  const { db, license } = ctx;

  router.get("/logs", async (req: Request, res: Response) => {
    const scoped = readScope(ctx, req, res);
    if (scoped === undefined) return;
    try {
      const { limit } = req.query;
      const wf = workspaceFilter(scoped?.id ?? null);
      const filter = logFilterSql(req.query);
      let sql = `SELECT * FROM agent_logs WHERE 1=1${wf.sql}${filter.sql}`;
      const params: unknown[] = [...wf.params, ...filter.params];

      const parsedLimit = Math.min(Math.max(Math.trunc(Number(limit)) || 100, 1), 1000);
      sql += " ORDER BY id DESC LIMIT ?";
      params.push(parsedLimit);

      const rows = await db.all<Record<string, unknown>>(sql, params);
      // Snapshots and responses can be large: keep list responses lean (GET /logs/:id has them).
      res.json(
        rows.map((row) => {
          const r: Record<string, unknown> = { ...row };
          r.has_snapshot = row.request_snapshot !== null;
          r.has_response = row.response_payload !== null;
          r.end_user_verified = row.end_user_verified === 1;
          r.sealed = row.row_hash !== null;
          r.workspace_slug = ctx.workspaces.get((row.workspace_id as number | null) ?? 1)?.slug ?? null;
          delete r.request_snapshot;
          delete r.response_payload;
          delete r.response_pending;
          delete r.prev_hash;
          return r;
        })
      );
    } catch (err) {
      sendInternalError(res, "Logs error", err, "Could not load audit logs.");
    }
  });

  /**
   * One audit row with everything recorded about it (all already redacted when stored):
   * the request (body / query / headers from the snapshot), the response, attribution and the
   * row's place in the hash chain.
   */
  router.get("/logs/:id", async (req: Request, res: Response, next: NextFunction) => {
    const raw = String(req.params.id);
    if (!/^\d+$/.test(raw)) return next(); // /logs/export.csv and friends
    const scoped = readScope(ctx, req, res);
    if (scoped === undefined) return;
    try {
      const wf = workspaceFilter(scoped?.id ?? null);
      const row = await db.get<Record<string, unknown>>(`SELECT * FROM agent_logs WHERE id = ?${wf.sql}`, [Number(raw), ...wf.params]);
      if (!row) {
        sendError(res, 404, "Not Found", `No audit row #${raw}.`);
        return;
      }
      const parse = (v: unknown): unknown => {
        if (typeof v !== "string") return null;
        try {
          return JSON.parse(v) as unknown;
        } catch {
          return v;
        }
      };
      const snapshot = parse(row.request_snapshot) as { body?: unknown; query?: unknown; headers?: unknown; truncated?: boolean; bodyUnknown?: boolean } | null;
      const out: Record<string, unknown> = { ...row };
      delete out.request_snapshot;
      out.workspace_slug = ctx.workspaces.get((row.workspace_id as number | null) ?? 1)?.slug ?? null;
      out.sealed = row.row_hash !== null;
      out.end_user_verified = row.end_user_verified === 1;
      out.response_pending = row.response_pending === 1 && row.row_hash === null;
      out.request =
        snapshot && typeof snapshot === "object"
          ? {
              body: snapshot.body ?? null,
              query: snapshot.query ?? null,
              headers: snapshot.headers ?? null,
              ...(snapshot.truncated ? { truncated: true } : {}),
              ...(snapshot.bodyUnknown ? { bodyUnknown: true } : {}),
            }
          : null;
      out.response = parse(row.response_payload);
      delete out.response_payload;
      res.json(out);
    } catch (err) {
      sendInternalError(res, "Log detail error", err, "Could not load the audit row.");
    }
  });

  // Traffic analytics. Rows are bucketed in SQL by integer-dividing the unix time
  // by the bucket size, so the buckets line up exactly with the ones built below.
  router.get("/logs/analytics", async (req: Request, res: Response) => {
    const scoped = readScope(ctx, req, res);
    if (scoped === undefined) return;
    const wf = workspaceFilter(scoped?.id ?? null);
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
      const rows = await db.all<{ bucket: number; status: LogStatus; count: number }>(
        `SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket, status, COUNT(*) AS count
         FROM agent_logs
         WHERE timestamp >= ? AND status != 'QUEUED'${wf.sql}
         GROUP BY bucket, status`,
        [stepSec, cutoffIso, ...wf.params]
      );

      // 2. Get ONLY currently pending requests bucketed by when they were queued
      const pendingBuckets = await db.all<{ bucket: number; count: number }>(
        `SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket, COUNT(*) AS count
         FROM pending_actions
         WHERE status = 'PENDING' AND timestamp >= ?${wf.sql}
         GROUP BY bucket`,
        [stepSec, cutoffIso, ...wf.params]
      );

      // 3. Get total live pending count for the top KPI card
      const pendingCountRow = await db.get<{ count: number }>(
        `SELECT COUNT(*) as count FROM pending_actions WHERE status = 'PENDING'${wf.sql}`,
        wf.params
      );
      const actualPendingCount = pendingCountRow?.count ?? 0;

      // 4. Top Targeted Endpoints (combines resolved logs + currently pending actions)
      const topEndpoints = await db.all<{
        method: string;
        path: string;
        total: number;
        allowed: number;
        intervened: number;
      }>(
        `SELECT
           method,
           path,
           COUNT(*) AS total,
           SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN 1 ELSE 0 END) AS allowed,
           SUM(CASE WHEN status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED', 'PENDING') THEN 1 ELSE 0 END) AS intervened
         FROM (
           SELECT method, path, status FROM agent_logs WHERE timestamp >= ? AND status != 'QUEUED'${wf.sql}
           UNION ALL
           SELECT method, path, status FROM pending_actions WHERE status = 'PENDING' AND timestamp >= ?${wf.sql}
         )
         GROUP BY method, path
         ORDER BY total DESC, intervened DESC
         LIMIT 8`,
        [cutoffIso, ...wf.params, cutoffIso, ...wf.params]
      );

      // 5. Top Active AI Agents / Callers
      const topAgents = await db.all<{
        agent: string;
        total: number;
        allowed: number;
        intervened: number;
      }>(
        `SELECT
           ${AGENT_LABEL_SQL} AS agent,
           COUNT(*) AS total,
           SUM(CASE WHEN status IN ('ALLOWED', 'APPROVED') THEN 1 ELSE 0 END) AS allowed,
           SUM(CASE WHEN status IN ('BLOCKED', 'RATE_LIMITED', 'REJECTED') THEN 1 ELSE 0 END) AS intervened
         FROM agent_logs
         WHERE timestamp >= ? AND status != 'QUEUED'${wf.sql}
         GROUP BY agent
         ORDER BY total DESC, intervened DESC
         LIMIT 8`,
        [cutoffIso, ...wf.params]
      );

      const buckets = new Map<number, AnalyticsBucket>();
      for (let b = firstBucket; b <= lastBucket; b++) {
        buckets.set(b, {
          hour: new Date(b * stepMs).toISOString(),
          ALLOWED: 0,
          BLOCKED: 0,
          QUEUED: 0,
          RATE_LIMITED: 0,
          APPROVED: 0,
          REJECTED: 0,
          RESPONSE_BLOCKED: 0,
          RESPONSE_SCRUBBED: 0,
          total: 0,
        });
      }

      const totals: Record<LogStatus, number> = {
        ALLOWED: 0,
        BLOCKED: 0,
        QUEUED: actualPendingCount,
        RATE_LIMITED: 0,
        APPROVED: 0,
        REJECTED: 0,
        RESPONSE_BLOCKED: 0,
        RESPONSE_SCRUBBED: 0,
      };

      for (const r of rows) {
        if (!LOG_STATUSES.includes(r.status)) continue;
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
        statusTotals: LOG_STATUSES.map((status) => ({ status, count: totals[status] })).filter(
          (t) => t.count > 0 || (t.status === "QUEUED" && actualPendingCount > 0)
        ),
        hourly: Array.from(buckets.values()),
        topEndpoints,
        topAgents,
      });
    } catch (err) {
      sendInternalError(res, "Analytics error", err, "Could not load analytics.");
    }
  }); }