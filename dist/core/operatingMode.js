"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EMERGENCY_MODES = void 0;
exports.createEmergencyStore = createEmergencyStore;
exports.localTime = localTime;
exports.isWithinBusinessHours = isWithinBusinessHours;
exports.stricterMode = stricterMode;
exports.effectiveMode = effectiveMode;
exports.scheduleFor = scheduleFor;
exports.applyOperatingMode = applyOperatingMode;
/**
 * Shop-wide operating modes, applied on top of the per-endpoint rules:
 *
 *   lockdown       every agent request is refused (and nothing already queued can be approved)
 *   approval_only  everything the rules would ALLOW, except reads, waits for a human
 *   business hours outside the configured hours, the same as approval_only
 *
 * The emergency mode lives in SQLite and is re-read every couple of seconds, so flipping it
 * from the dashboard, the API or a Telegram command reaches every gateway process sharing the
 * database. If it cannot be read the gateway keeps the last known value (and at startup,
 * `ready` fails, so every request fails closed).
 */
const KEY = "emergency_state";
const NORMAL = { mode: "normal", reason: null, changedBy: null, changedAt: null };
exports.EMERGENCY_MODES = ["normal", "approval_only", "lockdown"];
const READ_METHODS = ["GET", "HEAD", "OPTIONS"];
function parse(value) {
    if (!value)
        return NORMAL;
    try {
        const raw = JSON.parse(value);
        const mode = exports.EMERGENCY_MODES.includes(raw.mode) ? raw.mode : "lockdown"; // unreadable = safest
        return {
            mode,
            reason: typeof raw.reason === "string" ? raw.reason : null,
            changedBy: typeof raw.changedBy === "string" ? raw.changedBy : null,
            changedAt: typeof raw.changedAt === "string" ? raw.changedAt : null,
        };
    }
    catch {
        return { ...NORMAL, mode: "lockdown", reason: "The stored emergency state was unreadable, so the gateway locked down." };
    }
}
function createEmergencyStore(db, refreshMs) {
    let state = NORMAL;
    let timer;
    const listeners = [];
    function apply(next) {
        const prev = state;
        state = next;
        if (prev.mode !== next.mode || prev.changedAt !== next.changedAt) {
            for (const l of listeners) {
                try {
                    l(next, prev);
                }
                catch (err) {
                    console.error("Emergency listener failed:", err);
                }
            }
        }
    }
    async function read() {
        const row = await db.get("SELECT value FROM system_settings WHERE key = ?", [KEY]);
        return parse(row?.value);
    }
    return {
        async load() {
            state = await read();
        },
        current: () => state,
        async set(mode, reason, changedBy) {
            const next = { mode, reason: reason && reason.trim() ? reason.trim().slice(0, 300) : null, changedBy, changedAt: new Date().toISOString() };
            await db.run("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", [KEY, JSON.stringify(next)]);
            apply(next);
            return next;
        },
        start() {
            if (timer)
                return;
            timer = setInterval(() => {
                read()
                    .then(apply)
                    .catch(() => undefined);
            }, refreshMs);
            timer.unref();
        },
        stop() {
            if (timer)
                clearInterval(timer);
            timer = undefined;
        },
        onChange(listener) {
            listeners.push(listener);
        },
    };
}
// ---------------------------------------------------------------------------
// Time zone helpers
// ---------------------------------------------------------------------------
const WEEKDAYS = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
/** Local weekday (0 = Sunday), hour, minute and YYYY-MM-DD in an IANA time zone. */
function localTime(timeZone, now = new Date()) {
    const parts = new Intl.DateTimeFormat("en-US", {
        timeZone,
        weekday: "short",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hourCycle: "h23",
    }).formatToParts(now);
    const get = (t) => parts.find((p) => p.type === t)?.value ?? "";
    return {
        weekday: WEEKDAYS[get("weekday")] ?? 0,
        hour: Number(get("hour")) % 24,
        minute: Number(get("minute")),
        date: `${get("year")}-${get("month")}-${get("day")}`,
    };
}
const toMinutes = (hhmm) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));
/** Overnight ranges (22:00-06:00) count toward the day they started on. */
function isWithinBusinessHours(schedule, timeZone, now = new Date()) {
    const t = localTime(timeZone, now);
    const minute = t.hour * 60 + t.minute;
    const start = toMinutes(schedule.start);
    const end = toMinutes(schedule.end);
    if (start === end)
        return schedule.days.includes(t.weekday); // all day on the listed days
    if (start < end)
        return schedule.days.includes(t.weekday) && minute >= start && minute < end;
    if (minute >= start)
        return schedule.days.includes(t.weekday);
    if (minute < end)
        return schedule.days.includes((t.weekday + 6) % 7);
    return false;
}
/** The stricter of two modes (lockdown > approval_only > normal). */
function stricterMode(a, b) {
    const rank = { normal: 0, approval_only: 1, lockdown: 2 };
    return rank[a] >= rank[b] ? a : b;
}
/** Effective emergency mode for a workspace: the global switch and the workspace's own, whichever is stricter. */
function effectiveMode(ctx, workspace) {
    const global = ctx.emergency.current().mode;
    return workspace && !workspace.isDefault ? stricterMode(global, workspace.mode) : global;
}
/** Business hours for a workspace: its own override, else the global setting. */
function scheduleFor(ctx, workspace) {
    const s = ctx.settings.peek();
    return {
        schedule: workspace?.schedule ?? s.schedule,
        timezone: workspace?.timezone ?? s.timezone,
    };
}
/**
 * Applies lockdown / approval-only / business hours to a rule decision.
 * `kind` "mcp": tool calls cannot be told apart as reads, so approval-only holds all of them.
 */
function applyOperatingMode(ctx, decision, method, kind, workspace) {
    const mode = effectiveMode(ctx, workspace);
    if (mode === "lockdown")
        return { mode: "BLOCK", matched: "lockdown" };
    if (decision.mode !== "ALLOW")
        return decision;
    const isRead = kind === "http" && READ_METHODS.includes(method.toUpperCase());
    if (isRead)
        return decision;
    if (mode === "approval_only")
        return { mode: "REQUIRE_APPROVAL", matched: "approval-only mode" };
    const { schedule, timezone } = scheduleFor(ctx, workspace);
    if (schedule.enabled && !isWithinBusinessHours(schedule, timezone)) {
        return { mode: "REQUIRE_APPROVAL", matched: "outside business hours" };
    }
    return decision;
}
