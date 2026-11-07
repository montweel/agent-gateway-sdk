"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApprovalService = createApprovalService;
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const policy_1 = require("./policy");
const proxy_1 = require("./proxy");
const notify_1 = require("./notify");
const utils_1 = require("./utils");
const instance_1 = require("./instance");
const guards_1 = require("./guards");
const workspaces_1 = require("./workspaces");
const operatingMode_1 = require("./operatingMode");
const payloadPatch_1 = require("./payloadPatch");
const err = (status, error, message, extra = {}) => ({
    status,
    body: { error, message, ...extra },
});
/** Query object rebuilt from the original (unredacted) path, shaped like Express's simple parser output. */
function queryFromPath(path) {
    const q = path.indexOf("?");
    const out = {};
    if (q === -1)
        return out;
    const params = new URLSearchParams(path.slice(q + 1));
    for (const key of new Set(params.keys())) {
        const all = params.getAll(key);
        out[key] = all.length > 1 ? all : all[0];
    }
    return out;
}
function parseOrUndefined(text) {
    if (text === null)
        return undefined;
    try {
        return JSON.parse(text);
    }
    catch {
        return undefined;
    }
}
function createApprovalService(ctx) {
    const { db } = ctx;
    async function expireStale() {
        await db.run(`UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, patch_encrypted = NULL
       WHERE status IN ('PENDING', 'FAILED') AND expires_at IS NOT NULL AND expires_at <= ?`, [Date.now()]);
    }
    function bodyOf(row) {
        try {
            return row.body ? JSON.parse(row.body) : null;
        }
        catch {
            return null;
        }
    }
    const wsIdOf = (row) => row.workspace_id ?? constants_1.DEFAULT_WORKSPACE_ID;
    async function logDecision(row, status, actorName, detail, payloads = { original: null, modified: null }) {
        await db.run(`INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount, workspace_id, original_payload, modified_payload)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
            new Date().toISOString(),
            row.method,
            row.path,
            status,
            `decided_by:${actorName}`,
            row.agent_key ?? null,
            row.id,
            row.caller_ip ?? null,
            detail,
            // A revocation (BLOCKED) is not money protected a second time.
            status === "BLOCKED" ? null : (0, guards_1.extractAmount)(payloads.amountBody !== undefined ? payloads.amountBody : bodyOf(row)),
            wsIdOf(row),
            payloads.original,
            payloads.modified,
        ]);
        ctx.ledger.kick();
    }
    /** Human-approved spend counts toward the rule's budget. Never fails the approval. */
    async function recordApprovedSpend(row, executedBody) {
        try {
            const wsId = wsIdOf(row);
            const rulePath = (0, utils_1.normalizePath)(row.path.split("?")[0]);
            const entry = ctx.workspaces.lookupEntry(wsId, row.method, rulePath);
            if (!entry?.rule.budget)
                return;
            const body = executedBody ? JSON.parse(executedBody) : null;
            const callerId = row.agent_key_id !== null ? `key:${row.agent_key_id}` : `ip:${row.caller_ip ?? "unknown"}`;
            await ctx.guards.recordApproved((0, workspaces_1.scopedRuleKey)(wsId, entry.key), entry.rule, body, row.id, callerId);
        }
        catch (e) {
            console.error(`Could not record the approved spend for action ${row.id}:`, e);
        }
    }
    /** Decrypts the stored original request. Rows queued before encryption existed only have the redacted copy. */
    function original(row) {
        if (row.encrypted_payload === null)
            return { path: row.path, body: row.body, usedRedactedCopy: true };
        const parsed = JSON.parse((0, crypto_1.decryptPayload)(row.encrypted_payload, ctx.config.replayEncryptionKey()));
        if (typeof parsed.path !== "string")
            throw new Error("Payload has no path.");
        return { path: parsed.path, body: typeof parsed.body === "string" ? parsed.body : null, usedRedactedCopy: false };
    }
    /** Applies the approver's edits (if any) to the original request. Throws PatchError on bad input. */
    function prepare(row, orig, edits) {
        const base = { ...orig, edited: false, originalPayload: null, modifiedPayload: null, modifiedBody: null, modifiedQuery: null, changes: [] };
        if (!edits || (edits.body === undefined && edits.query === undefined))
            return base;
        const isMcp = row.kind === "mcp";
        if (isMcp && edits.query !== undefined)
            throw new payloadPatch_1.PatchError("MCP tool calls have no query string; edit the arguments (modifiedBody) instead.");
        const shownBody = row.body === null ? null : parseOrUndefined(row.body);
        let shownQuery = {};
        try {
            shownQuery = row.query_json ? JSON.parse(row.query_json) : {};
        }
        catch {
            shownQuery = {};
        }
        let body = orig.body;
        let path = orig.path;
        let newBody = shownBody;
        let newQuery = shownQuery;
        const changes = [];
        if (edits.body !== undefined) {
            (0, payloadPatch_1.assertJsonValue)(edits.body);
            if (isMcp && (typeof edits.body !== "object" || edits.body === null || Array.isArray(edits.body))) {
                throw new payloadPatch_1.PatchError("The edited tool arguments must be a JSON object.");
            }
            if (row.body !== null && shownBody === undefined) {
                throw new payloadPatch_1.PatchError("This request's body was too large (or not JSON) to show in full, so it cannot be edited. Approve or reject it as is.");
            }
            if (orig.usedRedactedCopy && row.body !== null && row.body.includes(constants_1.REDACTED)) {
                throw new payloadPatch_1.PatchError("This request was queued before encrypted replay existed; edit is unavailable because its original values are gone.");
            }
            if (!constants_1.NO_BODY_METHODS.includes(row.method) || isMcp) {
                const originalParsed = parseOrUndefined(orig.body);
                const merged = originalParsed === undefined ? edits.body : (0, payloadPatch_1.applyEdits)(originalParsed, shownBody ?? null, edits.body);
                body = JSON.stringify(merged);
                if (Buffer.byteLength(body) > constants_1.MAX_PENDING_BODY_BYTES)
                    throw new payloadPatch_1.PatchError(`The edited body must be at most ${constants_1.MAX_PENDING_BODY_BYTES / 1024} KB.`);
                newBody = edits.body;
                (0, payloadPatch_1.describeChanges)(shownBody ?? null, edits.body, isMcp ? "arguments" : "body", changes);
            }
            else {
                throw new payloadPatch_1.PatchError(`${row.method} requests have no body to edit.`);
            }
        }
        if (edits.query !== undefined) {
            const editedQuery = (0, payloadPatch_1.validateQueryEdit)(edits.query);
            const merged = (0, payloadPatch_1.applyEdits)(queryFromPath(orig.path), shownQuery, editedQuery);
            const clean = {};
            for (const [k, v] of Object.entries(merged)) {
                if (typeof v === "string" || (Array.isArray(v) && v.every((x) => typeof x === "string")))
                    clean[k] = v;
                else
                    throw new payloadPatch_1.PatchError(`Query parameter "${k}" must be a string or a list of strings.`);
            }
            path = (0, payloadPatch_1.withQuery)(orig.path, clean);
            newQuery = editedQuery;
            (0, payloadPatch_1.describeChanges)(shownQuery, editedQuery, "query", changes);
        }
        if (changes.length === 0)
            return base; // submitted unchanged: a plain approval
        const r = ctx.redactor;
        return {
            path,
            body,
            usedRedactedCopy: orig.usedRedactedCopy,
            edited: true,
            originalPayload: JSON.stringify({ body: shownBody ?? null, query: shownQuery }),
            modifiedPayload: JSON.stringify(r.json({ body: newBody ?? null, query: newQuery })),
            modifiedBody: edits.body !== undefined ? r.jsonText(JSON.stringify(edits.body)) : null,
            modifiedQuery: edits.query !== undefined ? JSON.stringify(r.json(newQuery)) : null,
            changes: changes.map((c) => r.text(c)),
        };
    }
    /** Replays a claimed (EXECUTING) action and records the outcome. */
    async function execute(row, req, actorName) {
        const id = row.id;
        const config = ctx.config.load();
        const ws = ctx.workspaces.get(wsIdOf(row));
        const upstream = ws?.upstreamUrl ?? config.targetUrl;
        const replayToSelf = upstream === "";
        const baseUrl = replayToSelf ? `http://127.0.0.1:${ctx.port}` : upstream;
        const saved = (0, utils_1.parseJsonObject)(row.headers);
        const replayHeaders = {};
        if (saved["content-type"])
            replayHeaders["content-type"] = saved["content-type"];
        if (saved["accept"])
            replayHeaders["accept"] = saved["accept"];
        if (saved["user-agent"])
            replayHeaders["user-agent"] = saved["user-agent"];
        const hasBody = req.body !== null && !constants_1.NO_BODY_METHODS.includes(row.method);
        if (hasBody && (!replayHeaders["content-type"] || req.edited))
            replayHeaders["content-type"] = "application/json";
        if (replayToSelf)
            replayHeaders[constants_1.REPLAY_HEADER] = ctx.replaySecret;
        // Content-Length is computed by fetch from the (possibly edited) body; it is never copied.
        const warning = req.usedRedactedCopy && (row.body?.includes(constants_1.REDACTED) || row.path.includes(encodeURIComponent(constants_1.REDACTED)))
            ? `This request was queued before encrypted replay existed, so its sensitive fields were replayed as "${constants_1.REDACTED}".`
            : undefined;
        try {
            const upstreamRes = await fetch(baseUrl + req.path, {
                method: row.method,
                headers: replayHeaders,
                body: hasBody ? req.body : undefined,
                redirect: "manual",
                signal: AbortSignal.timeout(constants_1.UPSTREAM_TIMEOUT_MS),
            });
            const text = (await (0, proxy_1.readCapped)(upstreamRes)).toString("utf-8");
            // The upstream reply is stored and shown to approvers: scrub it like everything else.
            const preview = ctx.redactor.text(`${upstreamRes.status} ${text.slice(0, 500)}`);
            // Done: the secrets are no longer needed, so wipe them for good.
            await db.run("UPDATE pending_actions SET status = 'APPROVED', response_preview = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ?", [preview, id]);
            await logDecision(row, "APPROVED", actorName, req.edited ? `edited by approver: ${req.changes.join("; ")}` : null, {
                original: req.originalPayload,
                modified: req.modifiedPayload,
                amountBody: req.edited ? parseOrUndefined(req.body) ?? null : undefined,
            });
            if (upstreamRes.status < 400)
                await recordApprovedSpend(row, req.body);
            return {
                status: 200,
                body: {
                    success: true,
                    id,
                    status: "APPROVED",
                    decided_by: actorName,
                    replayStatus: upstreamRes.status,
                    response_preview: preview,
                    ...(req.edited ? { edited: true, changes: req.changes } : {}),
                    ...(warning ? { warning } : {}),
                },
            };
        }
        catch (e) {
            // Not put back in the queue: the target may have received the request
            // before the failure, so a human must choose to RETRY.
            const timedOut = (0, proxy_1.isTimeoutError)(e);
            const reason = timedOut ? "the target did not respond in time" : "the target could not be reached";
            console.error("Replay failed:", e);
            await db.run("UPDATE pending_actions SET status = 'FAILED', response_preview = ? WHERE id = ?", [`Replay failed: ${reason}.`, id]).catch(() => undefined);
            return err(timedOut ? 504 : 502, timedOut ? "Gateway Timeout" : "Bad Gateway", `Replay failed (${reason}). The action is marked FAILED; an admin can retry it.`, {
                id,
                status: "FAILED",
            });
        }
    }
    async function decide(id, decision, actorName, edits) {
        await expireStale();
        const row = await db.get("SELECT * FROM pending_actions WHERE id = ?", [id]);
        if (!row)
            return err(404, "Not Found", `No pending action with id ${id}.`);
        if (row.status === "EXPIRED")
            return err(410, "Gone", `Action ${id} expired before it was decided. The agent must send it again.`);
        const wantsEdit = edits !== undefined && (edits.body !== undefined || edits.query !== undefined);
        if (wantsEdit && decision !== "APPROVE")
            return err(400, "Bad Request", "Edits can only be sent with an APPROVE decision.");
        if (wantsEdit && !ctx.license.current().features.payloadPatching) {
            return err(402, "Payment Required", "Edit & Approve is a Mont Pro feature. Approve or reject the request as is, or activate a Pro / Agency key.", {
                proRequired: true,
                feature: "payloadPatching",
            });
        }
        // ---- Reject (a PENDING or FAILED action) ----
        if (decision === "REJECT") {
            if (row.status !== "PENDING" && row.status !== "FAILED") {
                return err(409, "Conflict", `Action ${id} is ${row.status} and can no longer be rejected.`);
            }
            const result = await db.run("UPDATE pending_actions SET status = 'REJECTED', decided_by = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ? AND status = ?", [actorName, id, row.status]);
            if (result.changes === 0)
                return err(409, "Conflict", `Action ${id} was already decided.`);
            await logDecision(row, "REJECTED", actorName, null);
            // A held MCP call gets its answer right away.
            void ctx.mcpWaiters.get(id)?.onDecision("REJECT");
            return { status: 200, body: { success: true, id, status: "REJECTED", decided_by: actorName } };
        }
        if (row.kind === "mcp" && decision === "RETRY") {
            return err(409, "Conflict", `Action ${id} is an MCP tool call; the agent already received the failure. Ask it to call the tool again.`);
        }
        // ---- Approve (PENDING) or Retry (FAILED) ----
        // Lockdown (global or this client's) means nothing runs, including requests a human already looked at.
        const ws = ctx.workspaces.get(wsIdOf(row));
        if ((0, operatingMode_1.effectiveMode)(ctx, ws) === "lockdown") {
            return err(409, "Conflict", "The gateway is in emergency lockdown, so nothing can be executed. Resume normal mode first, or reject the request.");
        }
        const from = decision === "APPROVE" ? "PENDING" : "FAILED";
        if (row.status !== from) {
            return err(409, "Conflict", decision === "APPROVE" ? `Action ${id} is ${row.status}; only PENDING actions can be approved.` : `Action ${id} is ${row.status}; only FAILED actions can be retried.`);
        }
        // A caller blocked after this request was queued can never have it executed.
        const blocked = ctx.blocklist.match({ ip: row.caller_ip, agentKeyId: row.agent_key_id });
        if (blocked) {
            return err(409, "Conflict", `The caller of action ${id} has been blocked (${blocked.kind} ${blocked.label ?? blocked.value}). Reject it instead.`);
        }
        let orig;
        try {
            orig = original(row);
        }
        catch (e) {
            console.error(`Could not decrypt the stored request for action ${id}:`, e);
            await db
                .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ? WHERE id = ?", [
                "The stored request could not be decrypted (was config.json's replayEncryptionKey changed?). Reject it and ask the agent to send it again.",
                id,
            ])
                .catch(() => undefined);
            return err(500, "Internal Server Error", "The stored request could not be decrypted. Reject it and have the agent send it again.", {
                id,
                status: "FAILED",
            });
        }
        let req;
        try {
            req = prepare(row, orig, edits);
        }
        catch (e) {
            if (e instanceof payloadPatch_1.PatchError)
                return err(400, "Bad Request", e.message);
            throw e;
        }
        // The rule (or its payload policies) may have changed while the request waited. Re-check it now
        // against the payload that will actually run (the edited one, if edited), so tightening a
        // threshold also stops already-queued requests, and an edit can never exceed a hard BLOCK tier.
        const rulePath = (0, utils_1.normalizePath)(row.path.split("?")[0]);
        const entry = ctx.workspaces.lookupEntry(wsIdOf(row), row.method, rulePath);
        if (!entry) {
            return err(409, "Conflict", `${row.method} ${rulePath} no longer has a rule (default deny), so this action cannot run. Reject it instead.`);
        }
        const parsedBody = req.body !== null ? parseOrUndefined(req.body) : undefined;
        const verdict = (0, policy_1.evaluateRule)(entry.rule, {
            body: parsedBody,
            query: row.kind === "mcp" ? {} : queryFromPath(req.path),
            headers: row.kind === "mcp" ? {} : (0, utils_1.parseJsonObject)(row.headers),
        });
        if (verdict.mode === "BLOCK") {
            return err(409, "Conflict", req.edited
                ? `The edited request is BLOCKED by the rule for ${row.method} ${rulePath} (${verdict.matched}). Change the edit, or reject it.`
                : `The rule for ${row.method} ${rulePath} now BLOCKs this request (${verdict.matched}), so it cannot run. Reject it instead.`);
        }
        // A held MCP call in this process is reserved BEFORE the DB claim, so its own DB poll
        // cannot also pick up the EXECUTING status and run the call a second time.
        const localWaiter = row.kind === "mcp" ? ctx.mcpWaiters.get(id) : undefined;
        const reserved = localWaiter ? localWaiter.reserve() : false;
        // MCP calls held by another process need the edit too: it travels encrypted with the claim.
        const patchEncrypted = row.kind === "mcp" && req.edited ? (0, crypto_1.encryptPayload)(JSON.stringify({ arguments: parsedBody }), ctx.config.replayEncryptionKey()) : null;
        const claim = await db.run(`UPDATE pending_actions SET status = 'EXECUTING', decided_by = ?, modified_body = ?, modified_query = ?, patch_encrypted = ?
       WHERE id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)`, [actorName, req.modifiedBody, req.modifiedQuery, patchEncrypted, id, from, Date.now()]);
        if (claim.changes === 0) {
            if (reserved)
                localWaiter?.unreserve();
            return err(409, "Conflict", `Action ${id} was already decided or has expired.`);
        }
        if (row.kind === "mcp") {
            const result = await releaseMcp(row, actorName, reserved ? localWaiter : undefined, req, parsedBody);
            // In-process success, or released to the owning process (which will execute it).
            if (result.status === 200 || result.status === 202)
                await recordApprovedSpend(row, req.body);
            return result;
        }
        return execute(row, req, actorName);
    }
    /** APPROVE for a held MCP tool call: the waiting transport runs the call (with the approver's edits) now. */
    async function releaseMcp(row, actorName, waiter, req, args) {
        const id = row.id;
        const payloads = { original: req.originalPayload, modified: req.modifiedPayload, amountBody: req.edited ? (args ?? null) : undefined };
        const editNote = req.edited ? `; edited by approver: ${req.changes.join("; ")}` : "";
        if (!waiter && row.owner && row.owner !== ctx.instanceId && (0, instance_1.ownerAlive)(row.owner)) {
            // Another gateway process (e.g. a stdio MCP proxy) holds this call. The row is now
            // EXECUTING; that process sees it on its next poll, runs the call and records the result.
            await logDecision(row, "APPROVED", actorName, `mcp tool call released to its owning process${editNote}`, payloads);
            return {
                status: 202,
                body: {
                    success: true,
                    id,
                    status: "EXECUTING",
                    decided_by: actorName,
                    message: "Approved. The gateway process holding this tool call is executing it now.",
                    ...(req.edited ? { edited: true, changes: req.changes } : {}),
                },
            };
        }
        if (!waiter) {
            await db.run("UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, patch_encrypted = NULL, response_preview = ? WHERE id = ?", [
                "Expired: the agent stopped waiting before the approval, so the tool call was not executed.",
                id,
            ]);
            return err(410, "Gone", `The agent is no longer waiting for action ${id}, so it was not executed. It must call the tool again.`);
        }
        const out = await waiter.onDecision("APPROVE", req.edited ? { arguments: args } : undefined);
        const preview = ctx.redactor.text(out.preview).slice(0, 500);
        await db.run("UPDATE pending_actions SET status = ?, response_preview = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ?", [
            out.ok ? "APPROVED" : "FAILED",
            preview,
            id,
        ]);
        await logDecision(row, "APPROVED", actorName, `${out.ok ? "mcp tool call executed" : "mcp tool call failed"}${editNote}`, payloads);
        if (!out.ok)
            return err(502, "Bad Gateway", `The tool call was approved but failed: ${preview}`, { id, status: "FAILED" });
        return {
            status: 200,
            body: { success: true, id, status: "APPROVED", decided_by: actorName, response_preview: preview, ...(req.edited ? { edited: true, changes: req.changes } : {}) },
        };
    }
    async function fireRollback(row, actorName, reason, revokedAt) {
        const { url, secret } = ctx.settings.get().rollback;
        if (!url)
            return "NOT_CONFIGURED";
        if (!ctx.license.current().features.rollbackWebhooks)
            return "SKIPPED (compensating rollback webhooks need Mont Pro)";
        let body = null;
        try {
            body = row.modified_body ? JSON.parse(row.modified_body) : row.body ? JSON.parse(row.body) : null;
        }
        catch {
            body = row.body;
        }
        let query = {};
        try {
            query = row.modified_query ? JSON.parse(row.modified_query) : row.query_json ? JSON.parse(row.query_json) : {};
        }
        catch {
            query = {};
        }
        const ws = ctx.workspaces.get(wsIdOf(row));
        const payload = JSON.stringify({
            event: "approval.revoked",
            originalRequestId: row.id,
            workspace: ws ? { id: ws.id, slug: ws.slug, name: ws.name } : null,
            method: row.method,
            path: row.path,
            // The redacted copy of what actually ran (the approver's edit, if any): the unredacted
            // original was wiped when the action was decided.
            body,
            query,
            editedByApprover: row.modified_body !== null || row.modified_query !== null,
            caller: { ip: row.caller_ip, userAgent: row.caller_ua, agentKey: row.agent_key, agentKeyPrefix: row.agent_key_prefix },
            agentReason: row.agent_reason,
            approvedBy: row.decided_by,
            approvedAt: row.timestamp,
            upstreamResponsePreview: row.response_preview,
            revokedBy: actorName,
            revokedAt,
            reason,
        });
        const ts = String(Math.floor(Date.now() / 1000));
        const headers = {
            "content-type": "application/json",
            "x-mont-event": "approval.revoked",
            "x-mont-timestamp": ts,
            "idempotency-key": `mont-revoke-${row.id}`,
        };
        if (secret)
            headers["x-mont-signature"] = `sha256=${(0, notify_1.signWebhookBody)(secret, ts, payload)}`;
        try {
            const res = await fetch(url, {
                method: "POST",
                headers,
                body: payload,
                redirect: "error",
                signal: AbortSignal.timeout(constants_1.ROLLBACK_TIMEOUT_MS),
            });
            await res.body?.cancel().catch(() => undefined);
            return res.ok ? `SENT ${res.status}` : `FAILED HTTP ${res.status}`;
        }
        catch (e) {
            return `FAILED ${(0, proxy_1.isTimeoutError)(e) ? "timeout" : "unreachable"}`;
        }
    }
    async function revoke(id, options, actorName) {
        const row = await db.get("SELECT * FROM pending_actions WHERE id = ?", [id]);
        if (!row)
            return err(404, "Not Found", `No action with id ${id}.`);
        // FAILED is included: a failed replay may still have reached the target.
        if (row.status !== "APPROVED" && row.status !== "FAILED") {
            return err(409, "Conflict", `Action ${id} is ${row.status}. Only approved (or failed) actions can be revoked; reject pending ones instead.`);
        }
        if (row.revoked_at)
            return err(409, "Conflict", `Action ${id} was already revoked by ${row.revoked_by ?? "an admin"}.`);
        // (a) Kill-switch first: the most important effect must not depend on the rest succeeding.
        const blocks = [];
        if (options.blockAgentKey && row.agent_key_id !== null) {
            blocks.push({ kind: "agent_key", value: String(row.agent_key_id), label: row.agent_key ? `${row.agent_key}${row.agent_key_prefix ? ` (${row.agent_key_prefix}…)` : ""}` : null });
        }
        if (options.blockIp && row.caller_ip)
            blocks.push({ kind: "ip", value: row.caller_ip, label: row.caller_ip });
        if (blocks.length === 0) {
            return err(400, "Bad Request", "Nothing to block: this action has no recorded agent key or IP for the options chosen.");
        }
        const blocked = await ctx.blocklist.add(blocks, {
            createdBy: actorName,
            reason: options.reason,
            sourceActionId: row.id,
        });
        const revokedAt = new Date().toISOString();
        const claim = await db.run("UPDATE pending_actions SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL", [revokedAt, actorName, id]);
        if (claim.changes === 0)
            return err(409, "Conflict", `Action ${id} was revoked concurrently.`);
        // (b) Auto-reject everything this caller still has waiting.
        const keyId = blocks.some((b) => b.kind === "agent_key") ? row.agent_key_id : null;
        const ip = blocks.some((b) => b.kind === "ip") ? row.caller_ip : null;
        const waiting = await db.all(`SELECT * FROM pending_actions
       WHERE status IN ('PENDING', 'FAILED') AND id != ?
         AND ((? IS NOT NULL AND agent_key_id = ?) OR (? IS NOT NULL AND caller_ip = ?))`, [id, keyId, keyId, ip, ip]);
        const autoRejected = [];
        for (const w of waiting) {
            const r = await db.run("UPDATE pending_actions SET status = 'REJECTED', decided_by = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ? AND status = ?", [`auto:caller-blocked-by:${actorName}`, w.id, w.status]);
            if (r.changes > 0) {
                autoRejected.push(w.id);
                void ctx.mcpWaiters.get(w.id)?.onDecision("REJECT");
                await logDecision(w, "REJECTED", `auto:caller-blocked-by:${actorName}`, `Auto-rejected: caller blocked when action #${id} was revoked.`);
            }
        }
        // (c) Compensating rollback webhook (Pro).
        const rollbackStatus = options.fireRollback ? await fireRollback(row, actorName, options.reason, revokedAt) : "SKIPPED";
        await db.run("UPDATE pending_actions SET rollback_status = ? WHERE id = ?", [rollbackStatus, id]);
        await logDecision(row, "BLOCKED", actorName, `Revoked approval #${id}; blocked ${blocked.map((b) => `${b.kind}:${b.label ?? b.value}`).join(", ")}; auto-rejected ${autoRejected.length}; rollback ${rollbackStatus}.`);
        return {
            status: 200,
            body: {
                success: true,
                id,
                revokedAt,
                revokedBy: actorName,
                blocked,
                autoRejected,
                rollbackStatus,
            },
        };
    }
    return { expireStale, decide, revoke };
}
