import type { Request } from "express";
import type { Db } from "./db";
import type { AgentKeyRow } from "./types";
import { AGENT_KEY_HEADER, AGENT_KEY_PREFIX } from "./constants";
import { randomBase62, sha256Hex } from "./crypto";

export interface AgentKeyInfo {
  id: number;
  name: string;
}

export interface AgentKeyStore {
  /** Pulls a raw key out of `x-agent-key` or `Authorization: Bearer agk_...`. */
  extract(req: Request): string | undefined;
  /** Returns the key's identity if it exists, else null. */
  verify(raw: string): Promise<AgentKeyInfo | null>;
  list(): Promise<Array<{ id: number; name: string; keyPrefix: string; createdAt: string; lastUsedAt: string | null }>>;
  /** Creates a key. The raw value is returned once and only its SHA-256 is stored. */
  create(name: string): Promise<{ id: number; name: string; key: string; keyPrefix: string; createdAt: string }>;
  remove(id: number): Promise<boolean>;
}

const CACHE_TTL_MS = 30_000;
const LAST_USED_WRITE_INTERVAL_MS = 60_000;

export function createAgentKeyStore(db: Db): AgentKeyStore {
  // Keeps the per-request cost at a Map lookup instead of a DB read, and
  // limits last_used_at writes to once a minute per key.
  const cache = new Map<string, { info: AgentKeyInfo; checkedAt: number; lastWrite: number }>();

  function extract(req: Request): string | undefined {
    const header = req.get(AGENT_KEY_HEADER)?.trim();
    if (header) return header;
    const auth = req.get("authorization")?.trim();
    if (auth && auth.toLowerCase().startsWith("bearer ")) {
      const bearer = auth.slice(7).trim();
      if (bearer.startsWith(AGENT_KEY_PREFIX)) return bearer;
    }
    return undefined;
  }

  async function verify(raw: string): Promise<AgentKeyInfo | null> {
    if (!raw.startsWith(AGENT_KEY_PREFIX) || raw.length > 128) return null;
    const hash = sha256Hex(raw);
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

    const row = await db.get<AgentKeyRow>("SELECT * FROM agent_keys WHERE key_hash = ?", [hash]);
    if (!row) {
      cache.delete(hash);
      return null;
    }
    const info: AgentKeyInfo = { id: row.id, name: row.name };
    cache.set(hash, { info, checkedAt: now, lastWrite: now });
    void db
      .run("UPDATE agent_keys SET last_used_at = ? WHERE id = ?", [new Date(now).toISOString(), row.id])
      .catch(() => undefined);
    return info;
  }

  async function list() {
    const rows = await db.all<AgentKeyRow>("SELECT * FROM agent_keys ORDER BY id DESC");
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      keyPrefix: r.key_prefix,
      createdAt: r.created_at,
      lastUsedAt: r.last_used_at,
    }));
  }

  async function create(name: string) {
    const key = AGENT_KEY_PREFIX + randomBase62(24);
    const keyPrefix = key.slice(0, AGENT_KEY_PREFIX.length + 4);
    const createdAt = new Date().toISOString();
    const inserted = await db.run(
      "INSERT INTO agent_keys (name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, ?)",
      [name, keyPrefix, sha256Hex(key), createdAt]
    );
    return { id: inserted.lastID, name, key, keyPrefix, createdAt };
  }

  async function remove(id: number): Promise<boolean> {
    const result = await db.run("DELETE FROM agent_keys WHERE id = ?", [id]);
    cache.clear(); // a revoked key must stop working immediately
    return result.changes > 0;
  }

  return { extract, verify, list, create, remove };
}
