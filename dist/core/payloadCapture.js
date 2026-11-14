"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cleanEndUser = cleanEndUser;
exports.endUserOf = endUserOf;
exports.formatResponse = formatResponse;
exports.captureResponse = captureResponse;
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
const redactor_1 = require("./redactor");
/**
 * Compliance audit trail: who the agent acted for, and what came back.
 *
 *   endUserOf()        the human named in the SSO user header (x-forwarded-user by default) of an agent
 *                      request. VERIFIED only when the request also carries x-gateway-sso-secret matching
 *                      the configured SSO shared secret (the same proof the dashboard's SSO login needs),
 *                      i.e. the identity proxy vouches for it; otherwise it is the agent's own claim.
 *                      Recorded either way, never used for authorisation.
 *   captureResponse()  tees the bytes of a forwarded response (proxy mode and middleware mode) and,
 *                      once the response is finished, stores a redacted copy on the ALLOWED audit row.
 *                      The tee only copies; decoding and redaction run after the response is sent, so
 *                      they add nothing to the agent's latency.
 *   formatResponse()   the stored shape: {status, contentType, bytes, body, truncated?, note?}.
 *
 * Bodies are redacted FIRST and truncated after, so a large JSON body cannot slip a secret past the
 * key-based redactor by being cut mid-object.
 */
/** Raw bytes buffered for redaction. Larger bodies are not stored (only their size). */
const MAX_RAW_CAPTURE_BYTES = 1024 * 1024;
/** Sanitised end-user value: trimmed, control characters removed, secrets masked, capped. */
function cleanEndUser(raw) {
    if (typeof raw !== "string")
        return null;
    const clean = raw.replace(/[\u0000-\u001f\u007f]/g, "").trim();
    if (!clean)
        return null;
    return (0, redactor_1.scrubSecrets)(clean.slice(0, constants_1.MAX_END_USER_LENGTH)).text;
}
/** Who the agent acts for, and whether the trusted identity proxy vouched for it. */
function endUserOf(get, cfg) {
    const endUser = cleanEndUser(get(cfg.ssoUserHeader));
    if (endUser === null)
        return { endUser: null, verified: false };
    const secret = cfg.ssoSharedSecret;
    const verified = cfg.ssoTrustProxyHeader && secret.length >= 32 && (0, crypto_1.safeEqualStrings)(get(constants_1.SSO_SECRET_HEADER) ?? "", secret);
    return { endUser, verified };
}
const isTextual = (ct) => ct === null || ct === "" || /json|^text\/|xml|javascript|x-www-form-urlencoded|graphql/i.test(ct);
/** Redacted, size-capped JSON for agent_logs.response_payload. Never throws. */
function formatResponse(ctx, c) {
    const base = { status: c.status, contentType: c.contentType, bytes: c.bytes };
    const out = (extra) => JSON.stringify({ ...base, ...extra });
    try {
        if (c.note)
            return out({ body: null, note: c.note });
        if (c.bytes === 0)
            return out({ body: null });
        if (c.overflow || c.body.length > MAX_RAW_CAPTURE_BYTES)
            return out({ body: null, note: `body larger than ${MAX_RAW_CAPTURE_BYTES / 1024} KB; not stored` });
        if (!isTextual(c.contentType))
            return out({ body: null, note: "binary body not stored" });
        const text = c.body.toString("utf8");
        let parsed;
        let isJson = false;
        try {
            parsed = JSON.parse(text);
            isJson = true;
        }
        catch {
            // not JSON
        }
        if (isJson) {
            const redacted = ctx.redactor.json(parsed);
            const serialized = JSON.stringify(redacted);
            if (serialized.length <= constants_1.MAX_RESPONSE_CAPTURE_BYTES)
                return out({ body: redacted });
            // Already redacted, so cutting it is safe.
            return out({ body: `${serialized.slice(0, constants_1.MAX_RESPONSE_CAPTURE_BYTES)}…`, truncated: true });
        }
        // Looks like JSON but does not parse: key-based redaction cannot run on it, so it is not stored.
        if (/^\s*[[{]/.test(text))
            return out({ body: null, note: "malformed JSON body not stored (it could not be redacted reliably)" });
        const redacted = ctx.redactor.text(text);
        return redacted.length <= constants_1.MAX_RESPONSE_CAPTURE_BYTES
            ? out({ body: redacted })
            : out({ body: `${redacted.slice(0, constants_1.MAX_RESPONSE_CAPTURE_BYTES)}…`, truncated: true });
    }
    catch (err) {
        console.error("Could not format a captured response:", err);
        return out({ body: null, note: "capture failed" });
    }
}
/** Stores the response on its audit row and lets the ledger seal it. Best effort, never throws. */
async function store(ctx, logId, payload) {
    try {
        const r = await ctx.db.run("UPDATE agent_logs SET response_payload = ?, response_pending = NULL WHERE id = ? AND row_hash IS NULL", [payload, logId]);
        if (r.changes === 0)
            console.warn(`Audit row #${logId} was sealed before its response arrived; the response was not recorded.`);
        ctx.ledger.kick();
    }
    catch (err) {
        console.error(`Could not record the response for audit row #${logId}:`, err);
    }
}
function toBuffer(chunk, encoding) {
    if (chunk === undefined || chunk === null || typeof chunk === "function")
        return null;
    if (Buffer.isBuffer(chunk))
        return chunk;
    if (chunk instanceof Uint8Array)
        return Buffer.from(chunk);
    return Buffer.from(String(chunk), typeof encoding === "string" ? encoding : "utf8");
}
/**
 * Tees everything written to `res` and records it on audit row `logId` when the response ends.
 * Install it BEFORE any other res.write / res.end wrapper (e.g. the response guard), so what is
 * recorded is exactly what the agent received.
 */
function captureResponse(ctx, res, logId) {
    let done = false;
    const finalize = (c) => {
        if (done)
            return;
        done = true;
        // After the response: redaction never delays the agent.
        setImmediate(() => void store(ctx, logId, formatResponse(ctx, c)));
    };
    const contentType = () => {
        const v = res.getHeader("content-type");
        return v === undefined ? null : String(v);
    };
    const noted = (note) => ({ status: res.statusCode, contentType: contentType(), body: Buffer.alloc(0), overflow: false, bytes: size, note });
    let size = 0;
    if (res.destroyed || res.writableEnded) {
        finalize(noted("the client disconnected before the request was forwarded"));
        return;
    }
    const chunks = [];
    let overflow = false;
    let skip = null;
    const take = (chunk, encoding) => {
        if (done || skip)
            return;
        if (size === 0 && chunks.length === 0) {
            // Decided on the first bytes, when the headers are known.
            if (/event-stream/i.test(contentType() ?? "")) {
                skip = "event stream not stored";
                finalize(noted(skip)); // streams can stay open for hours: do not hold the ledger
                return;
            }
            const enc = res.getHeader("content-encoding");
            if (enc && String(enc).toLowerCase() !== "identity")
                skip = `${String(enc)}-encoded body not stored`;
        }
        const b = toBuffer(chunk, encoding);
        if (!b)
            return;
        size += b.length;
        if (skip)
            return;
        if (size > MAX_RAW_CAPTURE_BYTES) {
            overflow = true;
            chunks.length = 0;
        }
        else if (!overflow)
            chunks.push(b);
    };
    const origWrite = res.write.bind(res);
    const origEnd = res.end.bind(res);
    res.write = ((chunk, encoding, cb) => {
        take(chunk, encoding);
        return origWrite(chunk, encoding, cb);
    });
    res.end = ((chunk, encoding, cb) => {
        take(chunk, encoding);
        return origEnd(chunk, encoding, cb);
    });
    res.once("finish", () => {
        if (skip)
            return finalize(noted(skip));
        finalize({ status: res.statusCode, contentType: contentType(), body: Buffer.concat(chunks), overflow, bytes: size });
    });
    // "close" without "finish": the connection went away mid-response.
    res.once("close", () => finalize(noted("the client disconnected before the response completed")));
}
