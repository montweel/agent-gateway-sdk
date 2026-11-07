"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WorkspaceInputError = void 0;
exports.isValidWorkspaceSlug = isValidWorkspaceSlug;
exports.slugify = slugify;
exports.scopedRuleKey = scopedRuleKey;
exports.splitWorkspacePath = splitWorkspacePath;
exports.validateScheduleInput = validateScheduleInput;
exports.createWorkspaceStore = createWorkspaceStore;
exports.resolveWorkspace = resolveWorkspace;
const rules_1 = require("./rules");
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const settingsStore_1 = require("./settingsStore");
/** Validation errors from create / update (turned into 400s by the routes). */
class WorkspaceInputError extends Error {
    constructor(message) {
        super(message);
        this.name = "WorkspaceInputError";
    }
}
exports.WorkspaceInputError = WorkspaceInputError;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const RESERVED_SLUGS = new Set(["all", "default", "admin", "api", "w", "agent-admin", "_mont"]);
const TELEGRAM_CHAT = /^(?:-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/;
const SLACK_CHANNEL = /^[CGD][A-Z0-9]{6,20}$/;
const MODES = ["normal", "approval_only", "lockdown"];
function isValidWorkspaceSlug(slug) {
    return SLUG.test(slug);
}
/** "Acme Outfitters (EU)" -> "acme-outfitters-eu" */
function slugify(name) {
    return name
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 40)
        .replace(/-+$/g, "");
}
/** Budget / duplicate-ledger and rate-limit scope: the default workspace keeps its v1.x keys. */
function scopedRuleKey(workspaceId, ruleKey) {
    return workspaceId === constants_1.DEFAULT_WORKSPACE_ID ? ruleKey : `ws:${workspaceId}|${ruleKey}`;
}
/** Splits "/api/w/<slug>/rest?q" into the slug and "/api/rest?q". Null when the path has no workspace prefix. */
function splitWorkspacePath(url) {
    if (!url.startsWith(constants_1.WORKSPACE_PATH_PREFIX))
        return null;
    const after = url.slice(constants_1.WORKSPACE_PATH_PREFIX.length);
    const end = after.search(/[/?#]/);
    const slug = (end === -1 ? after : after.slice(0, end)).toLowerCase();
    if (!SLUG.test(slug))
        return null;
    const remainder = end === -1 ? "" : after.slice(end);
    return { slug, rest: `/api${remainder.startsWith("/") ? remainder : remainder ? `/${remainder}` : ""}` };
}
function parseSchedule(raw) {
    if (!raw)
        return null;
    try {
        const s = JSON.parse(raw);
        if (typeof s.enabled === "boolean" &&
            Array.isArray(s.days) &&
            s.days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6) &&
            typeof s.start === "string" &&
            settingsStore_1.HHMM.test(s.start) &&
            typeof s.end === "string" &&
            settingsStore_1.HHMM.test(s.end)) {
            return { enabled: s.enabled, days: [...new Set(s.days)].sort(), start: s.start, end: s.end };
        }
    }
    catch {
        // fall through
    }
    // Unreadable override: business hours ON for no day = every write outside hours = held (safest).
    return { enabled: true, days: [], start: "00:00", end: "00:00" };
}
/** Validates a schedule override from the API. null clears it (use the global schedule). */
function validateScheduleInput(raw) {
    if (raw === null)
        return { ok: true, value: null };
    if (typeof raw !== "object" || Array.isArray(raw))
        return { ok: false, message: "schedule must be an object or null." };
    const s = raw;
    if (typeof s.enabled !== "boolean")
        return { ok: false, message: "schedule.enabled must be true or false." };
    if (!Array.isArray(s.days) || !s.days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6)) {
        return { ok: false, message: "schedule.days must be a list of weekdays 0-6 (0 = Sunday)." };
    }
    if (typeof s.start !== "string" || !settingsStore_1.HHMM.test(s.start) || typeof s.end !== "string" || !settingsStore_1.HHMM.test(s.end)) {
        return { ok: false, message: 'schedule.start and schedule.end must be times like "09:00".' };
    }
    if (s.enabled && s.days.length === 0)
        return { ok: false, message: "Pick at least one business day, or turn business hours off." };
    return { ok: true, value: { enabled: s.enabled, days: [...new Set(s.days)].sort(), start: s.start, end: s.end } };
}
function toWorkspace(r) {
    return {
        id: r.id,
        name: r.name,
        slug: r.slug,
        isDefault: r.id === constants_1.DEFAULT_WORKSPACE_ID,
        apiKeyPrefix: r.api_key_prefix,
        hasApiKey: r.api_key_hash !== null,
        requireKey: r.require_key === 1,
        upstreamUrl: r.upstream_url || null,
        // Unreadable mode = safest.
        mode: MODES.includes(r.mode) ? r.mode : "lockdown",
        modeReason: r.mode_reason,
        modeChangedBy: r.mode_changed_by,
        modeChangedAt: r.mode_changed_at,
        telegramChatId: r.telegram_chat_id || null,
        slackChannel: r.slack_channel || null,
        timezone: r.timezone && (0, settingsStore_1.isValidTimeZone)(r.timezone) ? r.timezone : null,
        schedule: parseSchedule(r.schedule_json),
        createdAt: r.created_at,
        version: r.version,
    };
}
function parseRulesJson(raw, slug) {
    if (!raw)
        return {};
    try {
        return (0, rules_1.parseRulesObject)(JSON.parse(raw));
    }
    catch (err) {
        console.error(`Rules of workspace "${slug}" are not valid JSON; every path is blocked (default deny):`, err);
        return {};
    }
}
function newKey() {
    const raw = `${constants_1.WORKSPACE_KEY_PREFIX}${(0, crypto_1.randomBase62)(40)}`;
    return { raw, hash: (0, crypto_1.sha256Hex)(raw), prefix: raw.slice(0, constants_1.WORKSPACE_KEY_PREFIX.length + 6) };
}
function createWorkspaceStore(db, rulesStore, refreshMs) {
    const entries = new Map();
    const slugIndex = new Map();
    const keyIndex = new Map();
    const modeListeners = [];
    let timer;
    let loaded = false;
    function index() {
        slugIndex.clear();
        keyIndex.clear();
        for (const e of entries.values()) {
            slugIndex.set(e.ws.slug, e.ws.id);
            if (e.keyHash)
                keyIndex.set(e.keyHash, e.ws.id);
        }
    }
    function apply(rows) {
        const seen = new Set();
        for (const r of rows) {
            seen.add(r.id);
            const prev = entries.get(r.id);
            if (prev && prev.ws.version === r.version)
                continue;
            const ws = toWorkspace(r);
            const rules = ws.isDefault ? {} : parseRulesJson(r.rules_json, r.slug);
            entries.set(r.id, { ws, keyHash: r.api_key_hash, rules, lookup: (0, rules_1.matcherFor)(rules) });
            if (prev && loaded && prev.ws.mode !== ws.mode) {
                for (const l of modeListeners) {
                    try {
                        l(ws, prev.ws.mode);
                    }
                    catch (err) {
                        console.error("Workspace mode listener failed:", err);
                    }
                }
            }
        }
        for (const id of [...entries.keys()])
            if (!seen.has(id))
                entries.delete(id);
        index();
    }
    async function refresh() {
        apply(await db.all("SELECT * FROM workspaces ORDER BY id"));
        loaded = true;
    }
    async function reloadOne(id) {
        await refresh();
        const e = entries.get(id);
        if (!e)
            throw new Error(`Workspace ${id} disappeared.`);
        return e.ws;
    }
    function mustGet(id) {
        const e = entries.get(id);
        if (!e)
            throw new WorkspaceInputError(`No workspace with id ${id}.`);
        return e;
    }
    function nullableText(v, field, max) {
        if (v === null || v === "")
            return null;
        if (typeof v !== "string" || v.length > max)
            throw new WorkspaceInputError(`${field} must be a string of at most ${max} characters (or null).`);
        return v.trim() || null;
    }
    /** Validates the editable fields; returns column -> value for the ones present. */
    function columnsFrom(input, parseUpstream, isDefault) {
        const cols = {};
        if (input.name !== undefined) {
            if (typeof input.name !== "string" || !input.name.trim() || input.name.trim().length > 80)
                throw new WorkspaceInputError("name must be 1-80 characters.");
            cols.name = input.name.trim();
        }
        if (input.upstreamUrl !== undefined) {
            if (isDefault && input.upstreamUrl !== null && input.upstreamUrl !== "") {
                throw new WorkspaceInputError("The default workspace forwards to config.json's targetUrl; change it in Settings / Gateway Setup.");
            }
            if (input.upstreamUrl === null || input.upstreamUrl === "")
                cols.upstream_url = null;
            else {
                if (typeof input.upstreamUrl !== "string")
                    throw new WorkspaceInputError("upstreamUrl must be a string or null.");
                const parsed = parseUpstream(input.upstreamUrl);
                if (!parsed.ok)
                    throw new WorkspaceInputError(parsed.message.replace(/^targetUrl/, "upstreamUrl"));
                cols.upstream_url = parsed.url || null;
            }
        }
        if (input.requireKey !== undefined) {
            if (typeof input.requireKey !== "boolean")
                throw new WorkspaceInputError("requireKey must be true or false.");
            cols.require_key = input.requireKey ? 1 : 0;
        }
        if (input.telegramChatId !== undefined) {
            const c = nullableText(input.telegramChatId, "telegramChatId", 70);
            if (c !== null && !TELEGRAM_CHAT.test(c))
                throw new WorkspaceInputError("telegramChatId must be a number (e.g. -1001234567890) or @channelname.");
            cols.telegram_chat_id = c;
        }
        if (input.slackChannel !== undefined) {
            const c = nullableText(input.slackChannel, "slackChannel", 30);
            if (c !== null && !SLACK_CHANNEL.test(c))
                throw new WorkspaceInputError("slackChannel looks like C0123ABCD (copy it from the channel's details).");
            cols.slack_channel = c;
        }
        if (input.timezone !== undefined) {
            if (input.timezone === null || input.timezone === "")
                cols.timezone = null;
            else if (!(0, settingsStore_1.isValidTimeZone)(input.timezone))
                throw new WorkspaceInputError('timezone must be an IANA time zone such as "Europe/London" (or null).');
            else
                cols.timezone = input.timezone;
        }
        if (input.schedule !== undefined) {
            const s = validateScheduleInput(input.schedule);
            if (!s.ok)
                throw new WorkspaceInputError(s.message);
            cols.schedule_json = s.value === null ? null : JSON.stringify(s.value);
        }
        return cols;
    }
    async function updateColumns(id, cols) {
        const keys = Object.keys(cols);
        if (keys.length === 0)
            return;
        await db.run(`UPDATE workspaces SET ${keys.map((k) => `${k} = ?`).join(", ")}, version = version + 1 WHERE id = ?`, [...keys.map((k) => cols[k]), id]);
    }
    return {
        async load() {
            await refresh();
        },
        start() {
            if (timer)
                return;
            timer = setInterval(() => {
                refresh().catch((err) => console.error("Workspace refresh failed:", err));
            }, refreshMs);
            timer.unref();
        },
        stop() {
            if (timer)
                clearInterval(timer);
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
            if (!rawKey.startsWith(constants_1.WORKSPACE_KEY_PREFIX) || rawKey.length > 128)
                return undefined;
            const id = keyIndex.get((0, crypto_1.sha256Hex)(rawKey));
            return id === undefined ? undefined : entries.get(id)?.ws;
        },
        defaultWorkspace() {
            const e = entries.get(constants_1.DEFAULT_WORKSPACE_ID);
            if (e)
                return e.ws;
            // Before load(): a synthetic default (requests wait for `ready` anyway).
            return toWorkspace({
                id: constants_1.DEFAULT_WORKSPACE_ID,
                name: "Default",
                slug: constants_1.DEFAULT_WORKSPACE_SLUG,
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
            if (workspaceId === constants_1.DEFAULT_WORKSPACE_ID)
                return rulesStore.lookupEntry(method, endpoint);
            const e = entries.get(workspaceId);
            // Unknown workspace: nothing matches (default deny).
            return e ? e.lookup(method, endpoint) : undefined;
        },
        rules(workspaceId) {
            if (workspaceId === constants_1.DEFAULT_WORKSPACE_ID)
                return rulesStore.load();
            return { ...(entries.get(workspaceId)?.rules ?? {}) };
        },
        async saveRules(workspaceId, rules) {
            if (workspaceId === constants_1.DEFAULT_WORKSPACE_ID) {
                rulesStore.save(rules);
                return;
            }
            mustGet(workspaceId);
            await db.run("UPDATE workspaces SET rules_json = ?, version = version + 1 WHERE id = ?", [JSON.stringify(rules), workspaceId]);
            await refresh();
        },
        async create(input, parseUpstream) {
            if (typeof input.name !== "string" || !input.name.trim())
                throw new WorkspaceInputError("name is required.");
            const slug = typeof input.slug === "string" && input.slug.trim() ? input.slug.trim().toLowerCase() : slugify(input.name);
            if (!SLUG.test(slug))
                throw new WorkspaceInputError("slug must be 1-40 lowercase letters, digits or dashes (not starting or ending with a dash).");
            if (RESERVED_SLUGS.has(slug))
                throw new WorkspaceInputError(`"${slug}" is reserved; pick another slug.`);
            await refresh();
            if (slugIndex.has(slug))
                throw new WorkspaceInputError(`A workspace with slug "${slug}" already exists.`);
            const cols = columnsFrom(input, parseUpstream, false);
            const key = newKey();
            const all = {
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
            let id;
            try {
                const r = await db.run(`INSERT INTO workspaces (${keys.join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`, keys.map((k) => all[k]));
                id = r.lastID;
            }
            catch (err) {
                if (/UNIQUE/i.test(String(err)))
                    throw new WorkspaceInputError(`A workspace with slug "${slug}" already exists.`);
                throw err;
            }
            return { workspace: await reloadOne(id), apiKey: key.raw };
        },
        async update(id, input, parseUpstream) {
            const e = mustGet(id);
            if (input.slug !== undefined && input.slug !== e.ws.slug)
                throw new WorkspaceInputError("A workspace's slug cannot change (agents and URLs use it). Create a new workspace instead.");
            const cols = columnsFrom(input, parseUpstream, e.ws.isDefault);
            if (cols.require_key === 1 && !e.ws.hasApiKey)
                throw new WorkspaceInputError("Create an API key (rotate-key) before requiring one.");
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
            if (id === constants_1.DEFAULT_WORKSPACE_ID)
                throw new WorkspaceInputError("The default workspace cannot be deleted.");
            mustGet(id);
            await db.run("DELETE FROM workspaces WHERE id = ?", [id]);
            await refresh();
        },
        async setMode(id, mode, reason, changedBy) {
            const e = mustGet(id);
            const previous = e.ws.mode;
            await db.run("UPDATE workspaces SET mode = ?, mode_reason = ?, mode_changed_by = ?, mode_changed_at = ?, version = version + 1 WHERE id = ?", [mode, reason && reason.trim() ? reason.trim().slice(0, 300) : null, changedBy, new Date().toISOString(), id]);
            const ws = await reloadOne(id);
            // refresh() already notified listeners if the mode changed.
            void previous;
            return ws;
        },
        isEntitled(id, maxWorkspaces) {
            if (id === constants_1.DEFAULT_WORKSPACE_ID)
                return true;
            const others = [...entries.keys()].filter((k) => k !== constants_1.DEFAULT_WORKSPACE_ID).sort((a, b) => a - b);
            const rank = others.indexOf(id);
            return rank !== -1 && rank < maxWorkspaces - 1;
        },
        onModeChange(listener) {
            modeListeners.push(listener);
        },
    };
}
function resolveWorkspace(store, sel) {
    const headerSlug = sel.headerSlug?.trim().toLowerCase() || null;
    const pathSlug = sel.pathSlug?.trim().toLowerCase() || null;
    let keyWs;
    if (sel.key) {
        keyWs = store.byKey(sel.key);
        if (!keyWs)
            return { ok: false, status: 401, error: "Unauthorized", message: "The workspace API key is not valid.", reason: "invalid workspace key" };
    }
    if (headerSlug && pathSlug && headerSlug !== pathSlug) {
        return { ok: false, status: 400, error: "Bad Request", message: "The x-mont-workspace header and the /w/<slug>/ path name different workspaces.", reason: "conflicting workspace selectors" };
    }
    const slug = pathSlug ?? headerSlug;
    let named;
    if (slug) {
        named = store.bySlug(slug);
        if (!named)
            return { ok: false, status: 404, error: "Not Found", message: `Unknown workspace "${slug}".`, reason: "unknown workspace" };
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
            message: `Workspace "${workspace.slug}" requires its API key: send Authorization: Bearer ${constants_1.WORKSPACE_KEY_PREFIX}... (or x-agent-key).`,
            reason: "workspace key required",
        };
    }
    return { ok: true, workspace, authenticatedByKey };
}
