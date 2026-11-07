"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GENESIS_HASH = void 0;
exports.computeRowHash = computeRowHash;
exports.createAuditLedger = createAuditLedger;
const crypto_1 = __importDefault(require("crypto"));
/**
 * Tamper-evident, hash-chained audit ledger over agent_logs.
 *
 *   row_hash = SHA-256( prev_hash || "\n" || canonical JSON of
 *                [id, timestamp, caller, route, decision, redacted_payload, amount, workspace_id,
 *                 action_id, user_agent, shadow, original_payload, modified_payload] )
 *
 *   caller           = agent_key | caller_ip
 *   route            = "<METHOD> <path>"
 *   decision         = status (ALLOWED, BLOCKED, QUEUED, APPROVED, ...)
 *   redacted_payload = detail + request_snapshot (both redacted before they were stored)
 *
 * prev_hash of the first row is 64 zeros (or the retention checkpoint, below). Editing any field
 * of any row changes its hash; deleting a row breaks the next row's prev_hash link; deleting rows
 * from the end is caught by the stored head; truncating old rows is only allowed through the
 * retention checkpoint, which records the hash of the last row removed.
 *
 * Sealing is a deterministic function of the previous sealed row and the row itself, so any
 * number of gateway processes sharing one SQLite file can seal concurrently and always compute
 * identical values (each UPDATE is conditional on the row still being unsealed). Rows are written
 * unsealed by the request path (no extra latency, no lock) and sealed within about a second.
 *
 * Limits (also in the README): an attacker with write access to the database file can rewrite the
 * whole chain AND the head. To make that detectable too, the head hash is included in the daily
 * digest sent to your phone / Slack: an off-box copy of the chain's state.
 */
exports.GENESIS_HASH = "0".repeat(64);
const CHECKPOINT_KEY = "audit_chain_checkpoint";
const HEAD_KEY = "audit_chain_head";
const SEAL_BATCH = 500;
const VERIFY_PAGE = 2000;
const LEDGER_COLUMNS = "id, timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount, workspace_id, shadow, request_snapshot, original_payload, modified_payload, prev_hash, row_hash";
function computeRowHash(prevHash, r) {
    const caller = `${r.agent_key ?? ""}|${r.caller_ip ?? ""}`;
    const route = `${r.method} ${r.path}`;
    const payload = [r.detail ?? null, r.request_snapshot ?? null];
    const canonical = JSON.stringify([
        r.id,
        r.timestamp,
        caller,
        route,
        r.status,
        payload,
        r.amount ?? null,
        r.workspace_id ?? null,
        r.action_id ?? null,
        r.user_agent ?? null,
        r.shadow ?? null,
        r.original_payload ?? null,
        r.modified_payload ?? null,
    ]);
    return crypto_1.default.createHash("sha256").update(`${prevHash}\n${canonical}`, "utf8").digest("hex");
}
function parsePoint(value) {
    if (!value)
        return null;
    try {
        const p = JSON.parse(value);
        return typeof p.id === "number" && typeof p.hash === "string" && /^[0-9a-f]{64}$/.test(p.hash) ? { id: p.id, hash: p.hash } : null;
    }
    catch {
        return null;
    }
}
function createAuditLedger(db) {
    let sealing = null;
    let again = false;
    let kickTimer;
    let interval;
    let stopped = false;
    async function setting(key) {
        return (await db.get("SELECT value FROM system_settings WHERE key = ?", [key]))?.value;
    }
    /** Stores a chain point, only ever moving it forward (other processes may race us). */
    async function advance(key, point) {
        await db.run(`INSERT INTO system_settings (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value
       WHERE CAST(json_extract(system_settings.value, '$.id') AS INTEGER) < CAST(json_extract(excluded.value, '$.id') AS INTEGER)`, [key, JSON.stringify(point)]);
    }
    async function sealOnce() {
        let total = 0;
        for (;;) {
            if (stopped)
                return total;
            const checkpoint = parsePoint(await setting(CHECKPOINT_KEY));
            const last = await db.get("SELECT id, row_hash FROM agent_logs WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1");
            let prev = last?.row_hash ?? checkpoint?.hash ?? exports.GENESIS_HASH;
            const after = last?.id ?? checkpoint?.id ?? 0;
            const rows = await db.all(`SELECT ${LEDGER_COLUMNS} FROM agent_logs WHERE row_hash IS NULL AND id > ? ORDER BY id LIMIT ?`, [after, SEAL_BATCH]);
            if (rows.length === 0)
                return total;
            let lastPoint = null;
            for (const r of rows) {
                const hash = computeRowHash(prev, r);
                const u = await db.run("UPDATE agent_logs SET prev_hash = ?, row_hash = ? WHERE id = ? AND row_hash IS NULL", [prev, hash, r.id]);
                if (u.changes === 0) {
                    // Another process sealed it first (same inputs, so the same hash): continue from its value.
                    const sealed = await db.get("SELECT row_hash FROM agent_logs WHERE id = ?", [r.id]);
                    if (!sealed?.row_hash)
                        break; // row vanished (pruned): start over from the new tail
                    prev = sealed.row_hash;
                }
                else {
                    prev = hash;
                    total++;
                }
                lastPoint = { id: r.id, hash: prev };
            }
            if (lastPoint)
                await advance(HEAD_KEY, lastPoint);
            if (rows.length < SEAL_BATCH)
                return total;
            // Long backlog (first start after an upgrade): let request traffic in between batches.
            await new Promise((r) => setImmediate(r));
        }
    }
    function sealPending() {
        if (sealing) {
            again = true;
            return sealing.then(() => (again ? sealPending() : 0));
        }
        again = false;
        sealing = sealOnce().finally(() => {
            sealing = null;
        });
        return sealing;
    }
    async function verify() {
        const checkpoint = parsePoint(await setting(CHECKPOINT_KEY));
        const storedHead = parsePoint(await setting(HEAD_KEY));
        const report = {
            ok: true,
            checked: 0,
            unsealed: 0,
            firstId: null,
            lastId: null,
            headHash: checkpoint?.hash ?? exports.GENESIS_HASH,
            checkpoint,
            storedHead,
            brokenAt: null,
            reason: null,
            verifiedAt: new Date().toISOString(),
        };
        const fail = (id, reason) => ({ ...report, ok: false, brokenAt: id, reason });
        let prev = checkpoint?.hash ?? exports.GENESIS_HASH;
        let after = checkpoint?.id ?? 0;
        let sawUnsealed = false;
        let headSeen = false;
        for (;;) {
            const rows = await db.all(`SELECT ${LEDGER_COLUMNS} FROM agent_logs WHERE id > ? ORDER BY id LIMIT ?`, [after, VERIFY_PAGE]);
            if (rows.length === 0)
                break;
            for (const r of rows) {
                after = r.id;
                if (r.row_hash === null) {
                    sawUnsealed = true;
                    report.unsealed++;
                    continue;
                }
                if (sawUnsealed)
                    return fail(r.id, `Row #${r.id} is sealed but an older row is not: rows were inserted or re-ordered by hand.`);
                if (r.prev_hash !== prev) {
                    return fail(r.id, report.checked === 0 && checkpoint === null
                        ? `The oldest row (#${r.id}) does not start the chain: older rows were deleted outside the retention process.`
                        : `Row #${r.id} does not link to the row before it: a row was deleted or replaced just before #${r.id}.`);
                }
                if (computeRowHash(prev, r) !== r.row_hash)
                    return fail(r.id, `Row #${r.id} was modified after it was written (its content no longer matches its hash).`);
                if (storedHead && r.id === storedHead.id) {
                    headSeen = true;
                    if (r.row_hash !== storedHead.hash)
                        return fail(r.id, `Row #${r.id} does not match the recorded chain head: the chain was rewritten.`);
                }
                prev = r.row_hash;
                report.checked++;
                report.firstId ?? (report.firstId = r.id);
                report.lastId = r.id;
            }
        }
        report.headHash = prev;
        if (storedHead && !headSeen && storedHead.id > (checkpoint?.id ?? 0)) {
            return fail(report.lastId, `The recorded chain head is row #${storedHead.id}, but ${report.lastId === null ? "no sealed rows remain" : `the newest sealed row is #${report.lastId}`}: rows were deleted from the end of the log.`);
        }
        return report;
    }
    async function prune(keep) {
        // The newest row that will be deleted; everything after it stays.
        const cutoff = await db.get("SELECT id, row_hash FROM agent_logs ORDER BY id DESC LIMIT 1 OFFSET ?", [keep]);
        if (!cutoff)
            return 0;
        if (!cutoff.row_hash) {
            await sealPending();
            return 0; // next cleanup round
        }
        // Checkpoint first: if the process dies between the two statements, verify still starts at the checkpoint.
        await advance(CHECKPOINT_KEY, { id: cutoff.id, hash: cutoff.row_hash });
        const r = await db.run("DELETE FROM agent_logs WHERE id <= ? AND row_hash IS NOT NULL", [cutoff.id]);
        return r.changes;
    }
    return {
        kick() {
            if (stopped || kickTimer)
                return;
            kickTimer = setTimeout(() => {
                kickTimer = undefined;
                sealPending().catch((err) => console.error("Audit ledger sealing failed:", err));
            }, 200);
            kickTimer.unref();
        },
        sealPending,
        verify,
        prune,
        head: async () => parsePoint(await setting(HEAD_KEY)),
        start(intervalMs = 5000) {
            stopped = false;
            if (interval)
                return;
            interval = setInterval(() => {
                sealPending().catch((err) => console.error("Audit ledger sealing failed:", err));
            }, intervalMs);
            interval.unref();
        },
        stop() {
            stopped = true;
            if (interval)
                clearInterval(interval);
            interval = undefined;
            if (kickTimer)
                clearTimeout(kickTimer);
            kickTimer = undefined;
        },
    };
}
