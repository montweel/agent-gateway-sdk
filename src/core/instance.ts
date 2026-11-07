import crypto from "crypto";
import os from "os";
import type { Db } from "./db";

/** "<hostname>:<pid>:<nonce>" for this process. */
export function newInstanceId(): string {
  return `${os.hostname()}:${process.pid}:${crypto.randomBytes(4).toString("hex")}`;
}

/**
 * True unless we can prove the owning process is gone. Owners on another host (a shared
 * database file over a network share) are assumed alive: we cannot check them.
 */
export function ownerAlive(owner: string | null): boolean {
  if (!owner) return false;
  const parts = owner.split(":");
  if (parts.length < 3) return false;
  const nonce = parts.pop();
  const pid = Number(parts.pop());
  const host = parts.join(":");
  if (!nonce || !Number.isInteger(pid) || pid <= 0) return false;
  if (host !== os.hostname()) return true;
  if (pid === process.pid) return true; // another gateway instance inside this process
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Held MCP calls whose owning process has died can never be executed: expire (PENDING) or
 * fail (EXECUTING) them. Calls held by other live processes sharing this database are left alone.
 */
export async function reapOrphanedMcp(db: Db, selfId: string): Promise<number> {
  const rows = await db.all<{ id: number; status: string; owner: string | null }>(
    "SELECT id, status, owner FROM pending_actions WHERE kind = 'mcp' AND status IN ('PENDING', 'EXECUTING')"
  );
  let reaped = 0;
  for (const r of rows) {
    // Our own rows cannot exist yet at startup; any other live owner keeps its calls.
    if (r.owner !== selfId && ownerAlive(r.owner)) continue;
    if (r.status === "PENDING") {
      await db.run(
        "UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'",
        ["Expired: the gateway process holding this MCP tool call stopped; it was never executed.", r.id]
      );
    } else {
      await db.run(
        "UPDATE pending_actions SET status = 'FAILED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'EXECUTING'",
        ["Interrupted: the gateway process stopped while this approved MCP tool call was running. Check the target.", r.id]
      );
    }
    reaped++;
  }
  return reaped;
}
