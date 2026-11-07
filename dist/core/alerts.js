"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAlerts = createAlerts;
const operatingMode_1 = require("./operatingMode");
const protection_1 = require("./protection");
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
const DEBOUNCE_MS = 15 * 60000;
function createAlerts(ctx, intervalMs) {
    let timer;
    /** True if this process won the right to send `key` now. */
    async function claim(key, debounceMs) {
        const now = Date.now();
        const r = await ctx.db.run(`INSERT INTO system_settings (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE CAST(system_settings.value AS INTEGER) <= ?`, [key, String(now), now - debounceMs]);
        return r.changes > 0;
    }
    function event(kind, key, title, lines) {
        if (!ctx.settings.peek().alerts.enabled)
            return;
        const once = key.startsWith("!");
        void claim(`alert:${kind}:${key}`, once ? Number.MAX_SAFE_INTEGER : DEBOUNCE_MS)
            .then((won) => (won ? ctx.notifier.sendAlert(title, lines) : undefined))
            .catch((err) => console.error("Alert failed:", err));
    }
    async function sendDigest() {
        const s = await (0, protection_1.buildSummary)(ctx, 24);
        return ctx.notifier.sendAlert("Mont daily digest", (0, protection_1.summaryLines)(s));
    }
    async function checkNow(now = new Date()) {
        const settings = ctx.settings.peek();
        const a = settings.alerts;
        if (a.enabled) {
            const since = new Date(now.getTime() - a.burstWindowMinutes * 60000).toISOString();
            const row = await ctx.db.get("SELECT COUNT(*) AS n FROM agent_logs WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED')", [since]);
            const n = row?.n ?? 0;
            if (n >= a.burstThreshold) {
                const top = await ctx.db.all(`SELECT method, path, COALESCE(agent_key, caller_ip, 'unknown') AS caller, COUNT(*) AS c FROM agent_logs
           WHERE timestamp >= ? AND status IN ('BLOCKED', 'RATE_LIMITED') GROUP BY method, path, caller ORDER BY c DESC LIMIT 3`, [since]);
                event("burst", "global", `⚠️ ${n} agent requests refused in ${a.burstWindowMinutes} min`, [
                    ...top.map((t) => `${t.method} ${t.path} from ${t.caller}: ${t.c}×`),
                    "An agent may be looping or under prompt injection. Reply /lockdown to stop all agent traffic.",
                ]);
            }
        }
        if (a.digestHour !== null) {
            const local = (0, operatingMode_1.localTime)(settings.timezone, now);
            if (local.hour === a.digestHour) {
                const r = await ctx.db.run("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)", [`digest:${local.date}`, String(now.getTime())]);
                if (r.changes > 0)
                    await sendDigest();
            }
        }
    }
    return {
        start() {
            if (timer)
                return;
            timer = setInterval(() => {
                checkNow().catch((err) => console.error("Alert check failed:", err));
            }, intervalMs);
            timer.unref();
        },
        stop() {
            if (timer)
                clearInterval(timer);
            timer = undefined;
        },
        event,
        checkNow,
        sendDigest,
    };
}
