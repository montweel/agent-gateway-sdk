import type { Db } from "./db";
import type { GatewayContext } from "./context";
import type { EmergencyMode, EmergencyState, ScheduleSettings } from "./types";
import type { PolicyDecision } from "./policy";
import type { Workspace } from "./workspaces";

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
const NORMAL: EmergencyState = { mode: "normal", reason: null, changedBy: null, changedAt: null };
export const EMERGENCY_MODES: EmergencyMode[] = ["normal", "approval_only", "lockdown"];
const READ_METHODS = ["GET", "HEAD", "OPTIONS"];

export interface EmergencyStore {
  load(): Promise<void>;
  current(): EmergencyState;
  set(mode: EmergencyMode, reason: string | null, changedBy: string): Promise<EmergencyState>;
  start(): void;
  stop(): void;
  /** Fires when the mode changes (also when another process changed it). */
  onChange(listener: (state: EmergencyState, previous: EmergencyState) => void): void;
}

function parse(value: string | undefined): EmergencyState {
  if (!value) return NORMAL;
  try {
    const raw = JSON.parse(value) as Partial<EmergencyState>;
    const mode = EMERGENCY_MODES.includes(raw.mode as EmergencyMode) ? (raw.mode as EmergencyMode) : "lockdown"; // unreadable = safest
    return {
      mode,
      reason: typeof raw.reason === "string" ? raw.reason : null,
      changedBy: typeof raw.changedBy === "string" ? raw.changedBy : null,
      changedAt: typeof raw.changedAt === "string" ? raw.changedAt : null,
    };
  } catch {
    return { ...NORMAL, mode: "lockdown", reason: "The stored emergency state was unreadable, so the gateway locked down." };
  }
}

export function createEmergencyStore(db: Db, refreshMs: number): EmergencyStore {
  let state: EmergencyState = NORMAL;
  let timer: NodeJS.Timeout | undefined;
  const listeners: Array<(s: EmergencyState, p: EmergencyState) => void> = [];

  function apply(next: EmergencyState): void {
    const prev = state;
    state = next;
    if (prev.mode !== next.mode || prev.changedAt !== next.changedAt) {
      for (const l of listeners) {
        try {
          l(next, prev);
        } catch (err) {
          console.error("Emergency listener failed:", err);
        }
      }
    }
  }

  async function read(): Promise<EmergencyState> {
    const row = await db.get<{ value: string }>("SELECT value FROM system_settings WHERE key = ?", [KEY]);
    return parse(row?.value);
  }

  return {
    async load() {
      state = await read();
    },
    current: () => state,
    async set(mode, reason, changedBy) {
      const next: EmergencyState = { mode, reason: reason && reason.trim() ? reason.trim().slice(0, 300) : null, changedBy, changedAt: new Date().toISOString() };
      await db.run("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", [KEY, JSON.stringify(next)]);
      apply(next);
      return next;
    },
    start() {
      if (timer) return;
      timer = setInterval(() => {
        read()
          .then(apply)
          .catch(() => undefined);
      }, refreshMs);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
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
const WEEKDAYS: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

/** Local weekday (0 = Sunday), hour, minute and YYYY-MM-DD in an IANA time zone. */
export function localTime(timeZone: string, now: Date = new Date()): { weekday: number; hour: number; minute: number; date: string } {
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
  const get = (t: string): string => parts.find((p) => p.type === t)?.value ?? "";
  return {
    weekday: WEEKDAYS[get("weekday")] ?? 0,
    hour: Number(get("hour")) % 24,
    minute: Number(get("minute")),
    date: `${get("year")}-${get("month")}-${get("day")}`,
  };
}

const toMinutes = (hhmm: string): number => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

/** Overnight ranges (22:00-06:00) count toward the day they started on. */
export function isWithinBusinessHours(schedule: ScheduleSettings, timeZone: string, now: Date = new Date()): boolean {
  const t = localTime(timeZone, now);
  const minute = t.hour * 60 + t.minute;
  const start = toMinutes(schedule.start);
  const end = toMinutes(schedule.end);
  if (start === end) return schedule.days.includes(t.weekday); // all day on the listed days
  if (start < end) return schedule.days.includes(t.weekday) && minute >= start && minute < end;
  if (minute >= start) return schedule.days.includes(t.weekday);
  if (minute < end) return schedule.days.includes((t.weekday + 6) % 7);
  return false;
}

/** The stricter of two modes (lockdown > approval_only > normal). */
export function stricterMode(a: EmergencyMode, b: EmergencyMode): EmergencyMode {
  const rank: Record<EmergencyMode, number> = { normal: 0, approval_only: 1, lockdown: 2 };
  return rank[a] >= rank[b] ? a : b;
}

/** Effective emergency mode for a workspace: the global switch and the workspace's own, whichever is stricter. */
export function effectiveMode(ctx: GatewayContext, workspace: Workspace | undefined): EmergencyMode {
  const global = ctx.emergency.current().mode;
  return workspace && !workspace.isDefault ? stricterMode(global, workspace.mode) : global;
}

/** Business hours for a workspace: its own override, else the global setting. */
export function scheduleFor(ctx: GatewayContext, workspace: Workspace | undefined): { schedule: ScheduleSettings; timezone: string } {
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
export function applyOperatingMode(ctx: GatewayContext, decision: PolicyDecision, method: string, kind: "http" | "mcp", workspace?: Workspace): PolicyDecision {
  const mode = effectiveMode(ctx, workspace);
  if (mode === "lockdown") return { mode: "BLOCK", matched: "lockdown" };
  if (decision.mode !== "ALLOW") return decision;
  const isRead = kind === "http" && READ_METHODS.includes(method.toUpperCase());
  if (isRead) return decision;
  if (mode === "approval_only") return { mode: "REQUIRE_APPROVAL", matched: "approval-only mode" };
  const { schedule, timezone } = scheduleFor(ctx, workspace);
  if (schedule.enabled && !isWithinBusinessHours(schedule, timezone)) {
    return { mode: "REQUIRE_APPROVAL", matched: "outside business hours" };
  }
  return decision;
}
