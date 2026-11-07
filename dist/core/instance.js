"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.newInstanceId = newInstanceId;
exports.ownerAlive = ownerAlive;
exports.reapOrphanedMcp = reapOrphanedMcp;
const crypto_1 = __importDefault(require("crypto"));
const os_1 = __importDefault(require("os"));
/** "<hostname>:<pid>:<nonce>" for this process. */
function newInstanceId() {
    return `${os_1.default.hostname()}:${process.pid}:${crypto_1.default.randomBytes(4).toString("hex")}`;
}
/**
 * True unless we can prove the owning process is gone. Owners on another host (a shared
 * database file over a network share) are assumed alive: we cannot check them.
 */
function ownerAlive(owner) {
    if (!owner)
        return false;
    const parts = owner.split(":");
    if (parts.length < 3)
        return false;
    const nonce = parts.pop();
    const pid = Number(parts.pop());
    const host = parts.join(":");
    if (!nonce || !Number.isInteger(pid) || pid <= 0)
        return false;
    if (host !== os_1.default.hostname())
        return true;
    if (pid === process.pid)
        return true; // another gateway instance inside this process
    try {
        process.kill(pid, 0);
        return true;
    }
    catch (err) {
        return err.code === "EPERM";
    }
}
/**
 * Held MCP calls whose owning process has died can never be executed: expire (PENDING) or
 * fail (EXECUTING) them. Calls held by other live processes sharing this database are left alone.
 */
async function reapOrphanedMcp(db, selfId) {
    const rows = await db.all("SELECT id, status, owner FROM pending_actions WHERE kind = 'mcp' AND status IN ('PENDING', 'EXECUTING')");
    let reaped = 0;
    for (const r of rows) {
        // Our own rows cannot exist yet at startup; any other live owner keeps its calls.
        if (r.owner !== selfId && ownerAlive(r.owner))
            continue;
        if (r.status === "PENDING") {
            await db.run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'", ["Expired: the gateway process holding this MCP tool call stopped; it was never executed.", r.id]);
        }
        else {
            await db.run("UPDATE pending_actions SET status = 'FAILED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'EXECUTING'", ["Interrupted: the gateway process stopped while this approved MCP tool call was running. Check the target.", r.id]);
        }
        reaped++;
    }
    return reaped;
}
