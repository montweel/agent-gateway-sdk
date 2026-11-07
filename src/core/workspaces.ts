import type { Db } from "./db";
import type { EmergencyMode, Rule, Rules, ScheduleSettings } from "./types";
import type { RulesStore } from "./rules";
import { matcherFor, parseRulesObject } from "./rules";
import { DEFAULT_WORKSPACE_ID, DEFAULT_WORKSPACE_SLUG, WORKSPACE_KEY_PREFIX, WORKSPACE_PATH_PREFIX } from "./constants";
import { randomBase62, sha256Hex } from "./crypto";
import { HHMM, isValidTimeZone } from "./settingsStore";

/**
 * Multi-tenant workspaces: one Mont installation protecting many client stores (an AI automation
 * agency with 20 Shopify clients, say). Each workspace has its own
 *
 *   rules            (budgets, duplicate protection and payload policies live inside the rules)
 *   upstream URL     (where its allowed requests are forwarded)
 *   emergency mode   (lockdown / approval-only for just that client)
 *   business hours   (optional time zone + schedule; null = the global one)
 *   approval routing (its own Telegram chat / Slack channel; null = the global one)
 *   API key          mws_..., required by default, so one client's agent cannot act on another's store
 *
 * Workspace 1 ("default") is the v1.x single-tenant setup: rules.json, config.json's targetUrl and
 * the global notification settings. An installation that never creates a workspace behaves
 * exactly as before.
 *
 * Requests pick a workspace by path prefix (/api/w/<slug>/...), the x-mont-workspace header, or
 * the workspace's bearer key (Authorization: Bearer mws_... / x-agent-key: mws_...). Conflicting
 * selectors are refused. Everything is cached in memory (hot path = Map lookups) and re-read from
 * SQLite every couple of seconds, so changes made by another process sharing the database apply.
 */

export interface Workspace {
  id: number;
  name: string;
  slug: string;
  isDefault: boolean;
  /** First characters of the API key, for display. Null when the workspace has no key. */
  apiKeyPrefix: string | null;
  hasApiKey: boolean;
  /** Requests must present this workspace's mws_ key. */
  requireKey: boolean;
  /** Overrides config.json's targetUrl for this workspace. Null = targetUrl (or the host app). */
  upstreamUrl: string | null;
  mode: EmergencyMode;
  modeReason: string | null;
  modeChangedBy: string | null;
  modeChangedAt: string | null;
  /** Approval notifications for this workspace go to this Telegram chat (null = the global chat). */
  telegramChatId: string | null;
  /** ... and this Slack channel in Socket Mode (null = the global channel). */
  slackChannel: string | null;
  /** Business-hours override (null = the global time zone / schedule). */
  timezone: string | null;
  schedule: ScheduleSettings | null;
  createdAt: string;
  version: number;
}

interface WorkspaceRow {
  id: number;
  name: string;
  slug: string;
  api_key_hash: string | null;
  api_key_prefix: string | null;
  require_key: number;
  upstream_url: string | null;
  mode: string;
  mode_reason: string | null;
  mode_changed_by: string | null;
  mode_changed_at: string | null;
  telegram_chat_id: string | null;
  slack_channel: string | null;
  rules_json: string | null;
  timezone: string | null;
  schedule_json: string | null;
  version: number;
  created_at: string;
}

type Lookup = (method: string, endpoint: string) => { key: string; rule: Rule } | undefined;

interface Entry {
  ws: Workspace;
  keyHash: string | null;
  /** Non-default workspaces only (the default one reads rules.json). */
  rules: Rules;
  lookup: Lookup;
}

export interface WorkspaceInput {
  name?: unknown;
  slug?: unknown;
  upstreamUrl?: unknown;
  requireKey?: unknown;
  telegramChatId?: unknown;
  slackChannel?: unknown;
  timezone?: unknown;
  schedule?: unknown;
}

export interface WorkspaceStore {
  load(): Promise<void>;
  start(): void;
  stop(): void;
  /** Re-reads every workspace from SQLite now. */
  refresh(): Promise<void>;
  list(): Workspace[];
  get(id: number | null | undefined): Workspace | undefined;
  bySlug(slug: string): Workspace | undefined;
  /** Workspace whose API key this is (constant-time hash lookup), or undefined. */
  byKey(rawKey: string): Workspace | undefined;
  defaultWorkspace(): Workspace;
  /** Rule lookup within a workspace (default = rules.json, same precedence rules everywhere). */
  lookupEntry(workspaceId: number, method: string, endpoint: string): { key: string; rule: Rule } | undefined;
  rules(workspaceId: number): Rules;
  saveRules(workspaceId: number, rules: Rules): Promise<void>;
  create(input: WorkspaceInput, parseUpstream: (v: string) => { ok: true; url: string } | { ok: false; message: string }): Promise<{ workspace: Workspace; apiKey: string }>;
  update(id: number, input: WorkspaceInput, parseUpstream: (v: string) => { ok: true; url: string } | { ok: false; message: string }): Promise<Workspace>;
  rotateKey(id: number): Promise<{ workspace: Workspace; apiKey: string }>;
  remove(id: number): Promise<void>;
  setMode(id: number, mode: EmergencyMode, reason: string | null, changedBy: string): Promise<Workspace>;
  /**
   * Whether the license covers this workspace: the default one always, the others in creation
   * order up to maxWorkspaces (so a downgrade disables the newest clients, never the oldest).
   */
  isEntitled(id: number, maxWorkspaces: number): boolean;
  /** Fires when a workspace's emergency mode changes (also when another process changed it). */
  onModeChange(listener: (ws: Workspace, previous: EmergencyMode) => void): void;
}

/** Validation errors from create / update (turned into 400s by the routes). */
export class WorkspaceInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkspaceInputError";
  }
}

const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const RESERVED_SLUGS = new Set(["all", "default", "admin", "api", "w", "agent-admin", "_mont"]);
const TELEGRAM_CHAT = /^(?:-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/;
const SLACK_CHANNEL = /^[CGD][A-Z0-9]{6,20}$/;
const MODES: EmergencyMode[] = ["normal", "approval_only", "lockdown"];

export function isValidWorkspaceSlug(slug: string): boolean {
  return SLUG.test(slug);
}

/** "Acme Outfitters (EU)" -> "acme-outfitters-eu" */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
}

/** Budget / duplicate-ledger and rate-limit scope: the default workspace keeps its v1.x keys. */
export function scopedRuleKey(workspaceId: number, ruleKey: string): string {
  return workspaceId === DEFAULT_WORKSPACE_ID ? ruleKey : `ws:${workspaceId}|${ruleKey}`;
}

/** Splits "/api/w/<slug>/rest?q" into the slug and "/api/rest?q". Null when the path has no workspace prefix. */
export function splitWorkspacePath(url: string): { slug: string; rest: string } | null {
  if (!url.startsWith(WORKSPACE_PATH_PREFIX)) return null;
  const after = url.slice(WORKSPACE_PATH_PREFIX.length);
  const end = after.search(/[/?#]/);
  const slug = (end === -1 ? after : after.slice(0, end)).toLowerCase();
  if (!SLUG.test(slug)) return null;
  const remainder = end === -1 ? "" : after.slice(end);
  return { slug, rest: `/api${remainder.startsWith("/") ? remainder : remainder ? `/${remainder}` : ""}` };
}

function parseSchedule(raw: string | null): ScheduleSettings | null {
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as Partial<ScheduleSettings>;
    if (
      typeof s.enabled === "boolean" &&
      Array.isArray(s.days) &&
      s.days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6) &&
      typeof s.start === "string" &&
      HHMM.test(s.start) &&
      typeof s.end === "string" &&
      HHMM.test(s.end)
    ) {
      return { enabled: s.enabled, days: [...new Set(s.days)].sort(), start: s.start, end: s.end };
    }
  } catch {
    // fall through
  }
  // Unreadable override: business hours ON for no day = every write outside hours = held (safest).
  return { enabled: true, days: [], start: "00:00", end: "00:00" };
}

/** Validates a schedule override from the API. null clears it (use the global schedule). */
export function validateScheduleInput(raw: unknown): { ok: true; value: ScheduleSettings | null } | { ok: false; message: string } {
  if (raw === null) return { ok: true, value: null };
  if (typeof raw !== "object" || Array.isArray(raw)) return { ok: false, message: "schedule must be an object or null." };
  const s = raw as Record<string, unknown>;
  if (typeof s.enabled !== "boolean") return { ok: false, message: "schedule.enabled must be true or false." };
  if (!Array.isArray(s.days) || !s.days.every((d) => Number.isInteger(d) && (d as number) >= 0 && (d as number) <= 6)) {
    return { ok: false, message: "schedule.days must be a list of weekdays 0-6 (0 = Sunday)." };
  }
  if (typeof s.start !== "string" || !HHMM.test(s.start) || typeof s.end !== "string" || !HHMM.test(s.end)) {
    return { ok: false, message: 'schedule.start and schedule.end must be times like "09:00".' };
  }
  if (s.enabled && s.days.length === 0) return { ok: false, message: "Pick at least one business day, or turn business hours off." };
  return { ok: true, value: { enabled: s.enabled, days: [...new Set(s.days as number[])].sort(), start: s.start, end: s.end } };
}

function toWorkspace(r: WorkspaceRow): Workspace {
  return {
    id: r.id,
    name: r.name,
    slug: r.slug,
    isDefault: r.id === DEFAULT_WORKSPACE_ID,
    apiKeyPrefix: r.api_key_prefix,
    hasApiKey: r.api_key_hash !== null,
    requireKey: r.require_key === 1,
    upstreamUrl: r.upstream_url || null,
    // Unreadable mode = safest.
    mode: MODES.includes(r.mode as EmergencyMode) ? (r.mode as EmergencyMode) : "lockdown",
    modeReason: r.mode_reason,
    modeChangedBy: r.mode_changed_by,
    modeChangedAt: r.mode_changed_at,
    telegramChatId: r.telegram_chat_id || null,
    slackChannel: r.slack_channel || null,
    timezone: r.timezone && isValidTimeZone(r.timezone) ? r.timezone : null,
    schedule: parseSchedule(r.schedule_json),
    createdAt: r.created_at,
    version: r.version,
  };
}

function parseRulesJson(raw: string | null, slug: string): Rules {
  if (!raw) return {};
  try {
    return parseRulesObject(JSON.parse(raw) as unknown);
  } catch (err) {
    console.error(`Rules of workspace "${slug}" are not valid JSON; every path is blocked (default deny):`, err);
    return {};
  }
}

function newKey(): { raw: string; hash: string; prefix: string } {
  const raw = `${WORKSPACE_KEY_PREFIX}${randomBase62(40)}`;
  return { raw, hash: sha256Hex(raw), prefix: raw.slice(0, WORKSPACE_KEY_PREFIX.length + 6) };
}

export function createWorkspaceStore(db: Db, rulesStore: RulesStore, refreshMs: number): WorkspaceStore {
  const entries = new Map<number, Entry>();
  const slugIndex = new Map<string, number>();
  const keyIndex = new Map<string, number>();
  const modeListeners: Array<(ws: Workspace, previous: EmergencyMode) => void> = [];
  let timer: NodeJS.Timeout | undefined;
  let loaded = false;

  function index(): void {
    slugIndex.clear();
    keyIndex.clear();
    for (const e of entries.values()) {
      slugIndex.set(e.ws.slug, e.ws.id);
      if (e.keyHash) keyIndex.set(e.keyHash, e.ws.id);
    }
  }

  function apply(rows: WorkspaceRow[]): void {
    const seen = new Set<number>();
    for (const r of rows) {
      seen.add(r.id);
      const prev = entries.get(r.id);
      if (prev && prev.ws.version === r.version) continue;
      const ws = toWorkspace(r);
      const rules = ws.isDefault ? {} : parseRulesJson(r.rules_json, r.slug);
      entries.set(r.id, { ws, keyHash: r.api_key_hash, rules, lookup: matcherFor(rules) });
      if (prev && loaded && prev.ws.mode !== ws.mode) {
        for (const l of modeListeners) {
          try {
            l(ws, prev.ws.mode);
          } catch (err) {
            console.error("Workspace mode listener failed:", err);
          }
        }
      }
    }
    for (const id of [...entries.keys()]) if (!seen.has(id)) entries.delete(id);
    index();
  }

  async function refresh(): Promise<void> {
    apply(await db.all<WorkspaceRow>("SELECT * FROM workspaces ORDER BY id"));
    loaded = true;
  }

  async function reloadOne(id: number): Promise<Workspace> {
    await refresh();
    const e = entries.get(id);
    if (!e) throw new Error(`Workspace ${id} disappeared.`);
    return e.ws;
  }

  function mustGet(id: number): Entry {
    const e = entries.get(id);
    if (!e) throw new WorkspaceInputError(`No workspace with id ${id}.`);
    return e;
  }

  function nullableText(v: unknown, field: string, max: number): string | null {
    if (v === null || v === "") return null;
    if (typeof v !== "string" || v.length > max) throw new WorkspaceInputError(`${field} must be a string of at most ${max} characters (or null).`);
    return v.trim() || null;
  }

  /** Validates the editable fields; returns column -> value for the ones present. */
  function columnsFrom(input: WorkspaceInput, parseUpstream: (v: string) => { ok: true; url: string } | { ok: false; message: string }, isDefault: boolean): Record<string, unknown> {
    const cols: Record<string, unknown> = {};
    if (input.name !== undefined) {
      if (typeof input.name !== "string" || !input.name.trim() || input.name.trim().length > 80) throw new WorkspaceInputError("name must be 1-80 characters.");
      cols.name = input.name.trim();
    }
    if (input.upstreamUrl !== undefined) {
      if (isDefault && input.upstreamUrl !== null && input.upstreamUrl !== "") {
        throw new WorkspaceInputError("The default workspace forwards to config.json's targetUrl; change it in Settings / Gateway Setup.");
      }
      if (input.upstreamUrl === null || input.upstreamUrl === "") cols.upstream_url = null;
      else {
        if (typeof input.upstreamUrl !== "string") throw new WorkspaceInputError("upstreamUrl must be a string or null.");
        const parsed = parseUpstream(input.upstreamUrl);
        if (!parsed.ok) throw new WorkspaceInputError(parsed.message.replace(/^targetUrl/, "upstreamUrl"));
        cols.upstream_url = parsed.url || null;
      }
    }
    if (input.requireKey !== undefined) {
      if (typeof input.requireKey !== "boolean") throw new WorkspaceInputError("requireKey must be true or false.");
      cols.require_key = input.requireKey ? 1 : 0;
    }
    if (input.telegramChatId !== undefined) {
      const c = nullableText(input.telegramChatId, "telegramChatId", 70);
      if (c !== null && !TELEGRAM_CHAT.test(c)) throw new WorkspaceInputError("telegramChatId must be a number (e.g. -1001234567890) or @channelname.");
      cols.telegram_chat_id = c;
    }
    if (input.slackChannel !== undefined) {
      const c = nullableText(input.slackChannel, "slackChannel", 30);
      if (c !== null && !SLACK_CHANNEL.test(c)) throw new WorkspaceInputError("slackChannel looks like C0123ABCD (copy it from the channel's details).");
      cols.slack_channel = c;
    }
    if (input.timezone !== undefined) {
      if (input.timezone === null || input.timezone === "") cols.timezone = null;
      else if (!isValidTimeZone(input.timezone)) throw new WorkspaceInputError('timezone must be an IANA time zone such as "Europe/London" (or null).');
      else cols.timezone = input.timezone;
    }
    if (input.schedule !== undefined) {
      const s = validateScheduleInput(input.schedule);
      if (!s.ok) throw new WorkspaceInputError(s.message);
      cols.schedule_json = s.value === null ? null : JSON.stringify(s.value);
    }
    return cols;
  }

  async function updateColumns(id: number, cols: Record<string, unknown>): Promise<void> {
    const keys = Object.keys(cols);
    if (keys.length === 0) return;
    await db.run(`UPDATE workspaces SET ${keys.map((k) => `${k} = ?`).join(", ")}, version = version + 1 WHERE id = ?`, [...keys.map((k) => cols[k]), id]);
  }

  return {
    async load() {
      await refresh();
    },
    start() {
      if (timer) return;
      timer = setInterval(() => {
        refresh().catch((err: unknown) => console.error("Workspace refresh failed:", err));
      }, refreshMs);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = undefined;
    },
    refresh,
    list: () => [...entries.values()].map((e) => e.ws).sort((a, b) => a.id - b.id),
    get: (id) => (typeof id === "number" ? entries.get(id)?.ws : undefined),
    bySlug(slug) {
      const id = slugIndex.get(slug.toLowerCase());
      return id === undefined ? undefined : entries.get(id)?.ws;
    },
    byKey(rawKey) {
      if (!rawKey.startsWith(WORKSPACE_KEY_PREFIX) || rawKey.length > 128) return undefined;
      const id = keyIndex.get(sha256Hex(rawKey));
      return id === undefined ? undefined : entries.get(id)?.ws;
    },
    defaultWorkspace() {
      const e = entries.get(DEFAULT_WORKSPACE_ID);
      if (e) return e.ws;
      // Before load(): a synthetic default (requests wait for `ready` anyway).
      return toWorkspace({
        id: DEFAULT_WORKSPACE_ID,
        name: "Default",
        slug: DEFAULT_WORKSPACE_SLUG,
        api_key_hash: null,
        api_key_prefix: null,
        require_key: 0,
        upstream_url: null,
        mode: "normal",
        mode_reason: null,
        mode_changed_by: null,
        mode_changed_at: null,
        telegram_chat_id: null,
        slack_channel: null,
        rules_json: null,
        timezone: null,
        schedule_json: null,
        version: 0,
        created_at: new Date(0).toISOString(),
      });
    },
    lookupEntry(workspaceId, method, endpoint) {
      if (workspaceId === DEFAULT_WORKSPACE_ID) return rulesStore.lookupEntry(method, endpoint);
      const e = entries.get(workspaceId);
      // Unknown workspace: nothing matches (default deny).
      return e ? e.lookup(method, endpoint) : undefined;
    },
    rules(workspaceId) {
      if (workspaceId === DEFAULT_WORKSPACE_ID) return rulesStore.load();
      return { ...(entries.get(workspaceId)?.rules ?? {}) };
    },
    async saveRules(workspaceId, rules) {
      if (workspaceId === DEFAULT_WORKSPACE_ID) {
        rulesStore.save(rules);
        return;
      }
      mustGet(workspaceId);
      await db.run("UPDATE workspaces SET rules_json = ?, version = version + 1 WHERE id = ?", [JSON.stringify(rules), workspaceId]);
      await refresh();
    },
    async create(input, parseUpstream) {
      if (typeof input.name !== "string" || !input.name.trim()) throw new WorkspaceInputError("name is required.");
      const slug = typeof input.slug === "string" && input.slug.trim() ? input.slug.trim().toLowerCase() : slugify(input.name);
      if (!SLUG.test(slug)) throw new WorkspaceInputError("slug must be 1-40 lowercase letters, digits or dashes (not starting or ending with a dash).");
      if (RESERVED_SLUGS.has(slug)) throw new WorkspaceInputError(`"${slug}" is reserved; pick another slug.`);
      await refresh();
      if (slugIndex.has(slug)) throw new WorkspaceInputError(`A workspace with slug "${slug}" already exists.`);
      const cols = columnsFrom(input, parseUpstream, false);
      const key = newKey();
      const all: Record<string, unknown> = {
        name: cols.name,
        slug,
        api_key_hash: key.hash,
        api_key_prefix: key.prefix,
        require_key: cols.require_key ?? 1,
        upstream_url: cols.upstream_url ?? null,
        telegram_chat_id: cols.telegram_chat_id ?? null,
        slack_channel: cols.slack_channel ?? null,
        timezone: cols.timezone ?? null,
        schedule_json: cols.schedule_json ?? null,
        rules_json: "{}",
        created_at: new Date().toISOString(),
      };
      const keys = Object.keys(all);
      let id: number;
      try {
        const r = await db.run(`INSERT INTO workspaces (${keys.join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`, keys.map((k) => all[k]));
        id = r.lastID;
      } catch (err) {
        if (/UNIQUE/i.test(String(err))) throw new WorkspaceInputError(`A workspace with slug "${slug}" already exists.`);
        throw err;
      }
      return { workspace: await reloadOne(id), apiKey: key.raw };
    },
    async update(id, input, parseUpstream) {
      const e = mustGet(id);
      if (input.slug !== undefined && input.slug !== e.ws.slug) throw new WorkspaceInputError("A workspace's slug cannot change (agents and URLs use it). Create a new workspace instead.");
      const cols = columnsFrom(input, parseUpstream, e.ws.isDefault);
      if (cols.require_key === 1 && !e.ws.hasApiKey) throw new WorkspaceInputError("Create an API key (rotate-key) before requiring one.");
      await updateColumns(id, cols);
      return reloadOne(id);
    },
    async rotateKey(id) {
      mustGet(id);
      const key = newKey();
      await db.run("UPDATE workspaces SET api_key_hash = ?, api_key_prefix = ?, version = version + 1 WHERE id = ?", [key.hash, key.prefix, id]);
      return { workspace: await reloadOne(id), apiKey: key.raw };
    },
    async remove(id) {
      if (id === DEFAULT_WORKSPACE_ID) throw new WorkspaceInputError("The default workspace cannot be deleted.");
      mustGet(id);
      await db.run("DELETE FROM workspaces WHERE id = ?", [id]);
      await refresh();
    },
    async setMode(id, mode, reason, changedBy) {
      const e = mustGet(id);
      const previous = e.ws.mode;
      await db.run(
        "UPDATE workspaces SET mode = ?, mode_reason = ?, mode_changed_by = ?, mode_changed_at = ?, version = version + 1 WHERE id = ?",
        [mode, reason && reason.trim() ? reason.trim().slice(0, 300) : null, changedBy, new Date().toISOString(), id]
      );
      const ws = await reloadOne(id);
      // refresh() already notified listeners if the mode changed.
      void previous;
      return ws;
    },
    isEntitled(id, maxWorkspaces) {
      if (id === DEFAULT_WORKSPACE_ID) return true;
      const others = [...entries.keys()].filter((k) => k !== DEFAULT_WORKSPACE_ID).sort((a, b) => a - b);
      const rank = others.indexOf(id);
      return rank !== -1 && rank < maxWorkspaces - 1;
    },
    onModeChange(listener) {
      modeListeners.push(listener);
    },
  };
}

// ---------------------------------------------------------------------------
// Request -> workspace resolution (HTTP interceptor and MCP guard)
// ---------------------------------------------------------------------------
export interface WorkspaceSelectors {
  /** From /api/w/<slug>/... */
  pathSlug: string | null;
  /** From the x-mont-workspace header (or an MCP proxy option). */
  headerSlug: string | null;
  /** A raw mws_ key from Authorization: Bearer / x-agent-key, if one was sent. */
  key: string | null;
}

export type WorkspaceResolution =
  | { ok: true; workspace: Workspace; authenticatedByKey: boolean }
  | { ok: false; status: number; error: string; message: string; reason: string };

export function resolveWorkspace(store: WorkspaceStore, sel: WorkspaceSelectors): WorkspaceResolution {
  const headerSlug = sel.headerSlug?.trim().toLowerCase() || null;
  const pathSlug = sel.pathSlug?.trim().toLowerCase() || null;

  let keyWs: Workspace | undefined;
  if (sel.key) {
    keyWs = store.byKey(sel.key);
    if (!keyWs) return { ok: false, status: 401, error: "Unauthorized", message: "The workspace API key is not valid.", reason: "invalid workspace key" };
  }
  if (headerSlug && pathSlug && headerSlug !== pathSlug) {
    return { ok: false, status: 400, error: "Bad Request", message: "The x-mont-workspace header and the /w/<slug>/ path name different workspaces.", reason: "conflicting workspace selectors" };
  }
  const slug = pathSlug ?? headerSlug;
  let named: Workspace | undefined;
  if (slug) {
    named = store.bySlug(slug);
    if (!named) return { ok: false, status: 404, error: "Not Found", message: `Unknown workspace "${slug}".`, reason: "unknown workspace" };
  }
  if (named && keyWs && named.id !== keyWs.id) {
    return { ok: false, status: 403, error: "Forbidden", message: "This API key belongs to a different workspace.", reason: "workspace key / selector mismatch" };
  }
  const workspace = named ?? keyWs ?? store.defaultWorkspace();
  const authenticatedByKey = keyWs !== undefined && keyWs.id === workspace.id;
  if (workspace.requireKey && !authenticatedByKey) {
    return {
      ok: false,
      status: 401,
      error: "Unauthorized",
      message: `Workspace "${workspace.slug}" requires its API key: send Authorization: Bearer ${WORKSPACE_KEY_PREFIX}... (or x-agent-key).`,
      reason: "workspace key required",
    };
  }
  return { ok: true, workspace, authenticatedByKey };
}
