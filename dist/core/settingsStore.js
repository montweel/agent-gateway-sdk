"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HHMM = void 0;
exports.defaultSettings = defaultSettings;
exports.isValidTimeZone = isValidTimeZone;
exports.coerceSettings = coerceSettings;
exports.createSettingsStore = createSettingsStore;
exports.readPersistedListenPort = readPersistedListenPort;
const sqlite3_1 = __importDefault(require("sqlite3"));
const crypto_1 = require("./crypto");
const SETTINGS_KEY = "gateway_settings_v1";
const SIGNING_SECRET_KEY = "approval_signing_secret";
function defaultSettings() {
    return {
        listenPort: null,
        publicBaseUrl: "",
        notifications: {
            slack: { enabled: false, mode: "webhook", webhookUrl: "", botToken: "", appToken: "", channelId: "", approverIds: "" },
            telegram: { enabled: false, mode: "polling", botToken: "", chatId: "", approverIds: "" },
            webhook: { enabled: false, url: "", secret: "" },
        },
        rollback: { url: "", secret: "" },
        privacy: { redactEmails: true, redactPhones: true },
        timezone: "UTC",
        schedule: { enabled: false, days: [1, 2, 3, 4, 5], start: "09:00", end: "18:00" },
        alerts: { enabled: true, burstThreshold: 10, burstWindowMinutes: 5, digestHour: null },
        responseGuard: { enabled: false, maxArrayItems: 200, onLargeArray: "block", onSecret: "scrub" },
    };
}
function isValidTimeZone(tz) {
    if (typeof tz !== "string" || tz.length === 0 || tz.length > 64)
        return false;
    try {
        new Intl.DateTimeFormat("en-US", { timeZone: tz });
        return true;
    }
    catch {
        return false;
    }
}
exports.HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;
const str = (v, fallback = "") => (typeof v === "string" ? v : fallback);
const bool = (v) => v === true;
/** Fills in anything missing or mistyped so a hand-edited or older row never crashes a reader. */
function coerceSettings(raw) {
    const d = defaultSettings();
    if (typeof raw !== "object" || raw === null || Array.isArray(raw))
        return d;
    const r = raw;
    const n = (typeof r.notifications === "object" && r.notifications !== null ? r.notifications : {});
    const rb = (typeof r.rollback === "object" && r.rollback !== null ? r.rollback : {});
    const pv = (typeof r.privacy === "object" && r.privacy !== null ? r.privacy : {});
    const sc = (typeof r.schedule === "object" && r.schedule !== null ? r.schedule : {});
    const al = (typeof r.alerts === "object" && r.alerts !== null ? r.alerts : {});
    const rg = (typeof r.responseGuard === "object" && r.responseGuard !== null ? r.responseGuard : {});
    const port = r.listenPort;
    return {
        listenPort: typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null,
        publicBaseUrl: str(r.publicBaseUrl),
        notifications: {
            slack: {
                enabled: bool(n.slack?.enabled),
                mode: n.slack?.mode === "socket" ? "socket" : "webhook",
                webhookUrl: str(n.slack?.webhookUrl),
                botToken: str(n.slack?.botToken),
                appToken: str(n.slack?.appToken),
                channelId: str(n.slack?.channelId),
                approverIds: str(n.slack?.approverIds),
            },
            telegram: {
                enabled: bool(n.telegram?.enabled),
                // Settings saved before v1.2 had no mode: they used links, keep them that way.
                mode: n.telegram?.mode === "polling" ? "polling" : n.telegram?.mode === "links" || n.telegram !== undefined ? "links" : "polling",
                botToken: str(n.telegram?.botToken),
                chatId: str(n.telegram?.chatId),
                approverIds: str(n.telegram?.approverIds),
            },
            webhook: { enabled: bool(n.webhook?.enabled), url: str(n.webhook?.url), secret: str(n.webhook?.secret) },
        },
        rollback: { url: str(rb.url), secret: str(rb.secret) },
        // Fail safe: anything but an explicit false keeps PII masking on.
        privacy: { redactEmails: pv.redactEmails !== false, redactPhones: pv.redactPhones !== false },
        timezone: isValidTimeZone(r.timezone) ? r.timezone : d.timezone,
        schedule: {
            enabled: bool(sc.enabled),
            days: Array.isArray(sc.days) && sc.days.every((x) => Number.isInteger(x) && x >= 0 && x <= 6)
                ? [...new Set(sc.days)].sort()
                : d.schedule.days,
            start: typeof sc.start === "string" && exports.HHMM.test(sc.start) ? sc.start : d.schedule.start,
            end: typeof sc.end === "string" && exports.HHMM.test(sc.end) ? sc.end : d.schedule.end,
        },
        alerts: {
            enabled: al.enabled !== false,
            burstThreshold: Number.isInteger(al.burstThreshold) && al.burstThreshold >= 1 ? al.burstThreshold : d.alerts.burstThreshold,
            burstWindowMinutes: Number.isInteger(al.burstWindowMinutes) && al.burstWindowMinutes >= 1 && al.burstWindowMinutes <= 1440
                ? al.burstWindowMinutes
                : d.alerts.burstWindowMinutes,
            digestHour: Number.isInteger(al.digestHour) && al.digestHour >= 0 && al.digestHour <= 23 ? al.digestHour : null,
        },
        responseGuard: {
            enabled: bool(rg.enabled),
            maxArrayItems: Number.isInteger(rg.maxArrayItems) && rg.maxArrayItems >= 1 && rg.maxArrayItems <= 1000000
                ? rg.maxArrayItems
                : d.responseGuard.maxArrayItems,
            // Fail safe: anything unreadable picks the stricter action.
            onLargeArray: rg.onLargeArray === "truncate" ? "truncate" : "block",
            onSecret: rg.onSecret === "block" || (rg.onSecret !== undefined && rg.onSecret !== "scrub") ? "block" : "scrub",
        },
    };
}
function createSettingsStore(db) {
    let cached = null;
    let signingSecret = null;
    async function load() {
        const row = await db.get("SELECT value FROM system_settings WHERE key = ?", [SETTINGS_KEY]);
        if (row) {
            try {
                cached = coerceSettings(JSON.parse(row.value));
            }
            catch (err) {
                // Settings only drive notifications and the listen port, never enforcement, so a
                // corrupt row falls back to defaults (nothing is sent) instead of refusing to boot.
                console.error("Stored gateway settings are not valid JSON; using defaults:", err);
                cached = defaultSettings();
            }
        }
        else {
            cached = defaultSettings();
        }
        const secretRow = await db.get("SELECT value FROM system_settings WHERE key = ?", [SIGNING_SECRET_KEY]);
        if (secretRow && /^[0-9a-f]{64}$/i.test(secretRow.value)) {
            signingSecret = secretRow.value;
        }
        else {
            const secret = (0, crypto_1.randomHex)(32);
            await db.run("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", [SIGNING_SECRET_KEY, secret]);
            signingSecret = secret;
        }
    }
    function get() {
        if (!cached)
            throw new Error("Gateway settings are not loaded yet.");
        return structuredClone(cached);
    }
    async function save(next) {
        const clean = coerceSettings(next);
        await db.run("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", [SETTINGS_KEY, JSON.stringify(clean)]);
        cached = clean;
        for (const l of listeners) {
            try {
                l();
            }
            catch (err) {
                console.error("Settings listener failed:", err);
            }
        }
        return structuredClone(clean);
    }
    function approvalSigningSecret() {
        if (!signingSecret)
            throw new Error("The approval signing secret is not loaded yet.");
        return signingSecret;
    }
    const listeners = [];
    const MASK_ALL = { redactEmails: true, redactPhones: true };
    return {
        load,
        get,
        save,
        approvalSigningSecret,
        privacy: () => cached?.privacy ?? MASK_ALL,
        peek: () => cached ?? defaultSettings(),
        onChange: (l) => {
            listeners.push(l);
        },
    };
}
/**
 * Reads the persisted listen port without starting the gateway (the CLI needs the port
 * before it can create the gateway). Returns null when the database or the row does not exist.
 */
function readPersistedListenPort(dbPath) {
    return new Promise((resolve) => {
        const db = new sqlite3_1.default.Database(dbPath, sqlite3_1.default.OPEN_READONLY, (openErr) => {
            if (openErr) {
                resolve(null);
                return;
            }
            db.get("SELECT value FROM system_settings WHERE key = ?", [SETTINGS_KEY], (err, row) => {
                let port = null;
                if (!err && row?.value) {
                    try {
                        port = coerceSettings(JSON.parse(row.value)).listenPort;
                    }
                    catch {
                        port = null;
                    }
                }
                db.close(() => resolve(port));
            });
        });
    });
}
