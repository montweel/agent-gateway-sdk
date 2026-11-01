"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAgentKeyStore = createAgentKeyStore;
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const CACHE_TTL_MS = 30000;
const LAST_USED_WRITE_INTERVAL_MS = 60000;
function createAgentKeyStore(db) {
    // Keeps the per-request cost at a Map lookup instead of a DB read, and
    // limits last_used_at writes to once a minute per key.
    const cache = new Map();
    function extract(req) {
        const header = req.get(constants_1.AGENT_KEY_HEADER)?.trim();
        if (header)
            return header;
        const auth = req.get("authorization")?.trim();
        if (auth && auth.toLowerCase().startsWith("bearer ")) {
            const bearer = auth.slice(7).trim();
            if (bearer.startsWith(constants_1.AGENT_KEY_PREFIX))
                return bearer;
        }
        return undefined;
    }
    async function verify(raw) {
        if (!raw.startsWith(constants_1.AGENT_KEY_PREFIX) || raw.length > 128)
            return null;
        const hash = (0, crypto_1.sha256Hex)(raw);
        const now = Date.now();
        const hit = cache.get(hash);
        if (hit && now - hit.checkedAt < CACHE_TTL_MS) {
            if (now - hit.lastWrite >= LAST_USED_WRITE_INTERVAL_MS) {
                hit.lastWrite = now;
                void db
                    .run("UPDATE agent_keys SET last_used_at = ? WHERE id = ?", [new Date(now).toISOString(), hit.info.id])
                    .catch(() => undefined);
            }
            return hit.info;
        }
        const row = await db.get("SELECT * FROM agent_keys WHERE key_hash = ?", [hash]);
        if (!row) {
            cache.delete(hash);
            return null;
        }
        const info = { id: row.id, name: row.name };
        cache.set(hash, { info, checkedAt: now, lastWrite: now });
        void db
            .run("UPDATE agent_keys SET last_used_at = ? WHERE id = ?", [new Date(now).toISOString(), row.id])
            .catch(() => undefined);
        return info;
    }
    async function list() {
        const rows = await db.all("SELECT * FROM agent_keys ORDER BY id DESC");
        return rows.map((r) => ({
            id: r.id,
            name: r.name,
            keyPrefix: r.key_prefix,
            createdAt: r.created_at,
            lastUsedAt: r.last_used_at,
        }));
    }
    async function create(name) {
        const key = constants_1.AGENT_KEY_PREFIX + (0, crypto_1.randomBase62)(24);
        const keyPrefix = key.slice(0, constants_1.AGENT_KEY_PREFIX.length + 4);
        const createdAt = new Date().toISOString();
        const inserted = await db.run("INSERT INTO agent_keys (name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, ?)", [name, keyPrefix, (0, crypto_1.sha256Hex)(key), createdAt]);
        return { id: inserted.lastID, name, key, keyPrefix, createdAt };
    }
    async function remove(id) {
        const result = await db.run("DELETE FROM agent_keys WHERE id = ?", [id]);
        cache.clear(); // a revoked key must stop working immediately
        return result.changes > 0;
    }
    return { extract, verify, list, create, remove };
}
