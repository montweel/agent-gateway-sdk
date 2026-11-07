import type { GatewayContext } from "./context";
import type { ChannelResult } from "./notify";
import { localTime } from "./operatingMode";
import { buildSummary, summaryLines } from "./protection";

/**
 * Security alerts and the daily digest, sent to every enabled channel (Telegram, Slack, webhook).
 *
 *   burst     >= burstThreshold BLOCKED / RATE_LIMITED requests within burstWindowMinutes
 *             (an agent looping, a prompt-injection attack in progress)
 *   budget    a spending budget was reached
 *   emergency lockdown / approval-only switched on or off
 *   digest    once a day at digestHour (local time): the protection summary
 *
 * De-duplication is stored in SQLite, so several gateway processes sharing one database send
 * each alert once, and a restart does not re-send the day's digest.
 */

const DEBOUNCE_MS = 15 * 60_000;

export interface Alerts {
  start(): void;
  stop(): void;
  /** Fire-and-forget: sends at most once per kind+key per 15 minutes (`key` "!..." = always once). */
  event(kind: string, key: string, title: string, lines: string[]): void;
  /** Runs the burst check and the digest schedule now (also on a timer). */
  checkNow(now?: Date): Promise<void>;
  sendDigest(): Promise<ChannelResult[]>;
}

export function createAlerts(ctx: GatewayContext, intervalMs: number): Alerts {
  let timer: NodeJS.Timeout | undefined;

  /** True if this process won the right to send `key` now. */
  async function claim(key: string, debounceMs: number): Promise<boolean> {
    const now = Date.now();
    const r = await ctx.db.run(
      `INSERT INTO system_settings (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE CAST(system_settings.value AS INTEGER) <= ?`,
      [key, String(now), now - debounceMs]
    );
    return r.changes > 0;
  }

  function event(kind: string, key: string, title: string, lines: string[]): void {
    if (!ctx.settings.peek().alerts.enabled) return;
    const once = key.startsWith("!");
    void claim(`alert:${kind}:${key}`, once ? Number.MAX_SAFE_INTEGER : DEBOUNCE_MS)
      .then((won) => (won ? ctx.notifier.sendAlert(title, lines) : undefined))
      .catch((err: unknown) => console.error("Alert failed:", err));
  }

  async function sendDigest(): Promise<ChannelResult[]> {
    const s = await buildSummary(ctx, 24);
    const lines = summaryLines(s);
    // An off-box copy of the audit chain's head: if the database is ever rewritten wholesale,
    // the hash in yesterday's message will no longer match GET /audit/verify.
    await ctx.ledger.sealPending().catch(() => undefined);
    const head = await ctx.ledger.head().catch(() => null);
    if (head) lines.push(`Audit ledger head: #${head.id} ${head.hash.slice(0, 16)}…`);
    const workspaces = ctx.workspaces.list();
    if (workspaces.length > 1) lines.push(`Workspaces: ${workspaces.length} (per-client numbers in the dashboard's All Clients view)`);
    return ctx.notifier.sendAlert("Mont daily digest", lines);
  }

  async function checkNow(now: Date = new Date()): Promise<void> {
    const settings = ctx.settings.peek();
    const a = settings.alerts;
    if (a.enabled) {
      const since = new Date(now.getTime() - a.burstWindowMinutes * 60_000).toISOString();
      const row = await ctx.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM agent_logs WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED')", [since]);
      const n = row?.n ?? 0;
      if (n >= a.burstThreshold) {
        const top = await ctx.db.all<{ method: string; path: string; caller: string; c: number }>(
          `SELECT method, path, COALESCE(agent_key, caller_ip, 'unknown') AS caller, COUNT(*) AS c FROM agent_logs
           WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED') GROUP BY method, path, caller ORDER BY c DESC LIMIT 3`,
          [since]
        );
        event("burst", "global", `⚠️ ${n} agent requests refused in ${a.burstWindowMinutes} min`, [
          ...top.map((t) => `${t.method} ${t.path} from ${t.caller}: ${t.c}×`),
          "An agent may be looping or under prompt injection. Reply /lockdown to stop all agent traffic.",
        ]);
      }
    }
    if (a.digestHour !== null) {
      const local = localTime(settings.timezone, now);
      if (local.hour === a.digestHour) {
        const r = await ctx.db.run("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)", [`digest:${local.date}`, String(now.getTime())]);
        if (r.changes > 0) await sendDigest();
      }
    }
  }

  return {
    start() {
      if (timer) return;
      timer = setInterval(() => {
        checkNow().catch((err: unknown) => console.error("Alert check failed:", err));
      }, intervalMs);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = undefined;
    },
    event,
    checkNow,
    sendDigest,
  };
}
