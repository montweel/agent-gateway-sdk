import type { Db } from "./db";
import type { BlockedCallerRow } from "./types";
import { bucketIp } from "./rateLimit";

export interface CallerIdentity {
  /** Raw client IP; normalised with bucketIp (IPv6 is blocked per /64). */
  ip: string | null;
  agentKeyId: number | null;
}

export interface NewBlock {
  kind: "agent_key" | "ip";
  value: string;
  label?: string | null;
}

/**
 * Persistent kill-switch list. Checked on every /api/* request from an in-memory copy,
 * so a block costs no DB read on the hot path. The copy is loaded at startup (startup
 * fails, and the gateway fails closed, if it cannot be read) and refreshed after every change.
 */
export interface CallerBlocklist {
  load(): Promise<void>;
  /** Returns the matching row, or null. Throws if the list was never loaded (the caller fails closed). */
  match(identity: CallerIdentity): BlockedCallerRow | null;
  add(entries: NewBlock[], meta: { createdBy: string; reason: string | null; sourceActionId: number | null }): Promise<BlockedCallerRow[]>;
  list(): Promise<BlockedCallerRow[]>;
  remove(id: number): Promise<boolean>;
}

export function createCallerBlocklist(db: Db): CallerBlocklist {
  let byIp: Map<string, BlockedCallerRow> | null = null;
  let byKey: Map<string, BlockedCallerRow> | null = null;

  async function load(): Promise<void> {
    const rows = await db.all<BlockedCallerRow>("SELECT * FROM blocked_callers");
    const ips = new Map<string, BlockedCallerRow>();
    const keys = new Map<string, BlockedCallerRow>();
    for (const r of rows) {
      if (r.kind === "ip") ips.set(r.value, r);
      else keys.set(r.value, r);
    }
    byIp = ips;
    byKey = keys;
  }

  function match(identity: CallerIdentity): BlockedCallerRow | null {
    if (!byIp || !byKey) throw new Error("The blocked-callers list is not loaded.");
    if (identity.agentKeyId !== null) {
      const hit = byKey.get(String(identity.agentKeyId));
      if (hit) return hit;
    }
    if (identity.ip) {
      const hit = byIp.get(bucketIp(identity.ip));
      if (hit) return hit;
    }
    return null;
  }

  async function add(
    entries: NewBlock[],
    meta: { createdBy: string; reason: string | null; sourceActionId: number | null }
  ): Promise<BlockedCallerRow[]> {
    const now = new Date().toISOString();
    for (const e of entries) {
      const value = e.kind === "ip" ? bucketIp(e.value) : e.value;
      await db.run(
        `INSERT OR IGNORE INTO blocked_callers (kind, value, label, reason, source_action_id, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [e.kind, value, e.label ?? null, meta.reason, meta.sourceActionId, meta.createdBy, now]
      );
    }
    await load();
    const result: BlockedCallerRow[] = [];
    for (const e of entries) {
      const value = e.kind === "ip" ? bucketIp(e.value) : e.value;
      const row = (e.kind === "ip" ? byIp : byKey)?.get(value);
      if (row) result.push(row);
    }
    return result;
  }

  async function list(): Promise<BlockedCallerRow[]> {
    return db.all<BlockedCallerRow>("SELECT * FROM blocked_callers ORDER BY id DESC");
  }

  async function remove(id: number): Promise<boolean> {
    const result = await db.run("DELETE FROM blocked_callers WHERE id = ?", [id]);
    await load();
    return result.changes > 0;
  }

  return { load, match, add, list, remove };
}
