"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDatabase = createDatabase;
const fs_1 = __importDefault(require("fs"));
const sqlite3_1 = __importDefault(require("sqlite3"));
const constants_1 = require("./constants");
const CREATE_AGENT_LOGS_SQL = `
  CREATE TABLE agent_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ALLOWED', 'BLOCKED', 'QUEUED', 'RATE_LIMITED', 'APPROVED', 'REJECTED', 'RESPONSE_BLOCKED', 'RESPONSE_SCRUBBED')),
    user_agent TEXT,
    agent_key TEXT,
    action_id INTEGER,
    caller_ip TEXT,
    detail TEXT,
    amount REAL,
    workspace_id INTEGER,
    shadow TEXT,
    request_snapshot TEXT,
    original_payload TEXT,
    modified_payload TEXT,
    prev_hash TEXT,
    row_hash TEXT
  )
`;
// v2.0 multi-tenant workspaces. Row 1 is the "default" workspace: rules.json, config.json's
// targetUrl and the global notification settings, so a v1.x install keeps working unchanged.
const CREATE_WORKSPACES_SQL = `
  CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    api_key_hash TEXT UNIQUE,
    api_key_prefix TEXT,
    require_key INTEGER NOT NULL DEFAULT 1,
    upstream_url TEXT,
    mode TEXT NOT NULL DEFAULT 'normal' CHECK (mode IN ('normal', 'approval_only', 'lockdown')),
    mode_reason TEXT,
    mode_changed_by TEXT,
    mode_changed_at TEXT,
    telegram_chat_id TEXT,
    slack_channel TEXT,
    rules_json TEXT,
    timezone TEXT,
    schedule_json TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  )
`;
// Budgets (kind 'spend') and duplicate fingerprints (kind 'dedupe'). See guards.ts.
const CREATE_GUARD_LEDGER_SQL = `
  CREATE TABLE IF NOT EXISTS guard_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('spend', 'dedupe')),
    caller TEXT,
    fingerprint TEXT,
    amount REAL,
    action_id INTEGER,
    ts INTEGER NOT NULL
  )
`;
// Columns added after the first release. Added with ALTER TABLE when missing.
const AGENT_LOGS_EXTRA_COLUMNS = {
    agent_key: "TEXT",
    action_id: "INTEGER",
    caller_ip: "TEXT",
    detail: "TEXT",
    amount: "REAL",
    workspace_id: "INTEGER",
    shadow: "TEXT",
    request_snapshot: "TEXT",
    original_payload: "TEXT",
    modified_payload: "TEXT",
    prev_hash: "TEXT",
    row_hash: "TEXT",
};
const PENDING_EXTRA_COLUMNS = {
    expires_at: "INTEGER",
    agent_key: "TEXT",
    encrypted_payload: "TEXT",
    query_json: "TEXT",
    caller_ip: "TEXT",
    caller_ua: "TEXT",
    agent_key_id: "INTEGER",
    agent_key_prefix: "TEXT",
    agent_reason: "TEXT",
    matched_policy: "TEXT",
    revoked_at: "TEXT",
    revoked_by: "TEXT",
    rollback_status: "TEXT",
    kind: "TEXT",
    owner: "TEXT",
    workspace_id: "INTEGER",
    modified_body: "TEXT",
    modified_query: "TEXT",
    patch_encrypted: "TEXT",
};
const CREATE_BLOCKED_CALLERS_SQL = `
  CREATE TABLE IF NOT EXISTS blocked_callers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('agent_key', 'ip')),
    value TEXT NOT NULL,
    label TEXT,
    reason TEXT,
    source_action_id INTEGER,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (kind, value)
  )
`;
const CREATE_PENDING_ACTIONS_SQL = `
  CREATE TABLE pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    headers TEXT,
    body TEXT,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'EXECUTING', 'APPROVED', 'REJECTED', 'FAILED', 'EXPIRED')),
    response_preview TEXT,
    decided_by TEXT,
    expires_at INTEGER,
    agent_key TEXT,
    encrypted_payload TEXT,
    query_json TEXT,
    caller_ip TEXT,
    caller_ua TEXT,
    agent_key_id INTEGER,
    agent_key_prefix TEXT,
    agent_reason TEXT,
    matched_policy TEXT,
    revoked_at TEXT,
    revoked_by TEXT,
    rollback_status TEXT,
    kind TEXT,
    owner TEXT,
    workspace_id INTEGER,
    modified_body TEXT,
    modified_query TEXT,
    patch_encrypted TEXT
  )
`;
const CREATE_USERS_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    otp_expires_at INTEGER,
    created_at TEXT NOT NULL
  )
`;
const CREATE_SESSIONS_SQL = `
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`;
const CREATE_AGENT_KEYS_SQL = `
  CREATE TABLE IF NOT EXISTS agent_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT
  )
`;
const CREATE_SYSTEM_SETTINGS_SQL = `
  CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )
`;
function createDatabase(dbPath) {
    const db = new sqlite3_1.default.Database(dbPath, (err) => {
        if (err)
            console.error(`Could not open ${dbPath}:`, err.message);
    });
    function run(sql, params = []) {
        return new Promise((resolve, reject) => {
            db.run(sql, params, function (err) {
                if (err)
                    reject(err);
                else
                    resolve({ lastID: this.lastID, changes: this.changes });
            });
        });
    }
    function all(sql, params = []) {
        return new Promise((resolve, reject) => {
            db.all(sql, params, (err, rows) => {
                if (err)
                    reject(err);
                else
                    resolve(rows);
            });
        });
    }
    function get(sql, params = []) {
        return new Promise((resolve, reject) => {
            db.get(sql, params, (err, row) => {
                if (err)
                    reject(err);
                else
                    resolve(row);
            });
        });
    }
    /**
     * SQLite cannot change a CHECK constraint in place, so a table whose schema is
     * out of date is rebuilt: rename, create the new one, copy the shared columns, drop.
     * `extra` supplies values for columns the old table did not have (name -> SQL literal).
     */
    async function rebuildTable(table, createSql, extra = {}) {
        console.log(`Migrating ${table} to the new schema...`);
        await run("BEGIN IMMEDIATE");
        try {
            const oldCols = (await all(`PRAGMA table_info(${table})`)).map((c) => c.name);
            await run(`ALTER TABLE ${table} RENAME TO ${table}_old`);
            await run(createSql);
            const newCols = (await all(`PRAGMA table_info(${table})`)).map((c) => c.name);
            const shared = newCols.filter((c) => oldCols.includes(c));
            const extraKeys = Object.keys(extra).filter((k) => !shared.includes(k));
            const cols = [...shared, ...extraKeys];
            const values = [...shared, ...extraKeys.map((k) => extra[k])];
            await run(`INSERT INTO ${table} (${cols.join(", ")}) SELECT ${values.join(", ")} FROM ${table}_old`);
            await run(`DROP TABLE ${table}_old`);
            await run("COMMIT");
        }
        catch (err) {
            await run("ROLLBACK").catch(() => undefined);
            throw err;
        }
    }
    async function tableSql(name) {
        const row = await get("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", [name]);
        return row ? (row.sql ?? "") : undefined;
    }
    async function hasColumn(table, column) {
        return (await all(`PRAGMA table_info(${table})`)).some((c) => c.name === column);
    }
    async function init() {
        // WAL lets readers and the single writer work at the same time, NORMAL
        // sync is safe with WAL, and busy_timeout waits instead of failing fast.
        await run("PRAGMA journal_mode = WAL");
        await run("PRAGMA synchronous = NORMAL");
        await run("PRAGMA busy_timeout = 5000");
        await run("PRAGMA foreign_keys = ON");
        // ---- agent_logs: the CHECK must list every status the code writes ----
        const logsSql = await tableSql("agent_logs");
        if (logsSql === undefined) {
            await run(CREATE_AGENT_LOGS_SQL);
        }
        else if (!logsSql.includes("'QUEUED'") ||
            !logsSql.includes("'RATE_LIMITED'") ||
            !logsSql.includes("'APPROVED'") ||
            !logsSql.includes("'REJECTED'") ||
            !logsSql.includes("'RESPONSE_BLOCKED'") ||
            !logsSql.includes("'RESPONSE_SCRUBBED'")) {
            // Values are copied unchanged (row hashes included), so a sealed ledger still verifies.
            await rebuildTable("agent_logs", CREATE_AGENT_LOGS_SQL);
        }
        for (const [column, type] of Object.entries(AGENT_LOGS_EXTRA_COLUMNS)) {
            if (!(await hasColumn("agent_logs", column))) {
                await run(`ALTER TABLE agent_logs ADD COLUMN ${column} ${type}`);
            }
        }
        // ---- pending_actions: approval state machine + expiry ----
        const pendingSql = await tableSql("pending_actions");
        if (pendingSql === undefined) {
            await run(CREATE_PENDING_ACTIONS_SQL);
        }
        else if (!pendingSql.includes("'EXECUTING'") || !pendingSql.includes("'EXPIRED'") || !pendingSql.includes("'FAILED'")) {
            // Rows that predate expiry get a fresh 24 hour window.
            await rebuildTable("pending_actions", CREATE_PENDING_ACTIONS_SQL, {
                expires_at: String(Date.now() + constants_1.PENDING_TTL_MS),
            });
        }
        for (const [column, type] of Object.entries(PENDING_EXTRA_COLUMNS)) {
            if (!(await hasColumn("pending_actions", column))) {
                await run(`ALTER TABLE pending_actions ADD COLUMN ${column} ${type}`);
            }
        }
        // Kill-switch list (Revoke & Block Caller).
        await run(CREATE_BLOCKED_CALLERS_SQL);
        await run(CREATE_GUARD_LEDGER_SQL);
        await run("CREATE INDEX IF NOT EXISTS idx_guard_ledger_lookup ON guard_ledger(rule_key, kind, ts)");
        await run("CREATE INDEX IF NOT EXISTS idx_guard_ledger_fp ON guard_ledger(rule_key, fingerprint)");
        // A decided or expired action must not keep its secrets.
        await run("UPDATE pending_actions SET encrypted_payload = NULL, patch_encrypted = NULL WHERE (encrypted_payload IS NOT NULL OR patch_encrypted IS NOT NULL) AND status IN ('APPROVED', 'REJECTED', 'EXPIRED')");
        // A request that was mid-replay when the process died has an unknown outcome.
        // (Held MCP calls belong to whichever process holds them; index.ts reaps only orphaned ones.)
        await run("UPDATE pending_actions SET status = 'FAILED', response_preview = 'Interrupted: the gateway restarted while this action was executing. Check the target before retrying.' WHERE status = 'EXECUTING' AND (kind IS NULL OR kind != 'mcp')");
        await run("CREATE INDEX IF NOT EXISTS idx_agent_logs_timestamp ON agent_logs(timestamp DESC)");
        await run("CREATE INDEX IF NOT EXISTS idx_agent_logs_status ON agent_logs(status)");
        await run("CREATE INDEX IF NOT EXISTS idx_agent_logs_method ON agent_logs(method)");
        await run("CREATE INDEX IF NOT EXISTS idx_agent_logs_status_ts ON agent_logs(status, timestamp)");
        await run("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status)");
        await run("CREATE INDEX IF NOT EXISTS idx_pending_caller_ip ON pending_actions(caller_ip)");
        await run("CREATE INDEX IF NOT EXISTS idx_pending_agent_key_id ON pending_actions(agent_key_id)");
        await run("CREATE INDEX IF NOT EXISTS idx_pending_workspace ON pending_actions(workspace_id, status)");
        await run("CREATE INDEX IF NOT EXISTS idx_agent_logs_workspace ON agent_logs(workspace_id, timestamp)");
        // The hash-chain sealer looks for the oldest unsealed rows.
        await run("CREATE INDEX IF NOT EXISTS idx_agent_logs_unsealed ON agent_logs(id) WHERE row_hash IS NULL");
        // ---- v2.0 workspaces (row 1 = default workspace, always present) ----
        await run(CREATE_WORKSPACES_SQL);
        await run("INSERT OR IGNORE INTO workspaces (id, name, slug, require_key, created_at) VALUES (1, 'Default', 'default', 0, ?)", [
            new Date().toISOString(),
        ]);
        // Rows written before workspaces existed belong to the default workspace. Sealed rows are
        // never touched (their workspace_id is part of the hash).
        await run("UPDATE agent_logs SET workspace_id = 1 WHERE workspace_id IS NULL AND row_hash IS NULL");
        await run("UPDATE pending_actions SET workspace_id = 1 WHERE workspace_id IS NULL");
        await run(CREATE_USERS_SQL);
        if (!(await hasColumn("users", "otp_expires_at"))) {
            await run("ALTER TABLE users ADD COLUMN otp_expires_at INTEGER");
        }
        await run(CREATE_SESSIONS_SQL);
        await run("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)");
        await run("DELETE FROM sessions WHERE expires_at <= ?", [Date.now()]);
        await run(CREATE_AGENT_KEYS_SQL);
        // The free Pro trial starts the first time this database boots, and never restarts.
        await run(CREATE_SYSTEM_SETTINGS_SQL);
        await run("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('trial_started_at', ?)", [
            String(Date.now()),
        ]);
        // The database holds password hashes and request bodies: keep it owner-only
        // (including the WAL side files, which hold the same data).
        for (const file of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
            try {
                fs_1.default.chmodSync(file, 0o600);
            }
            catch {
                // not fatal (the side files may not exist yet, or this is Windows)
            }
        }
    }
    return {
        run,
        all,
        get,
        init,
        close: () => new Promise((resolve, reject) => {
            db.close((err) => (err ? reject(err) : resolve()));
        }),
    };
}
