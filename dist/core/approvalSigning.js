"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signApprovalLink = signApprovalLink;
exports.verifyApprovalLink = verifyApprovalLink;
exports.parseCallbackDecision = parseCallbackDecision;
exports.signButtonToken = signButtonToken;
exports.parseButtonToken = parseButtonToken;
exports.verifyButtonToken = verifyButtonToken;
exports.buildApprovalLink = buildApprovalLink;
const crypto_1 = __importDefault(require("crypto"));
const constants_1 = require("./constants");
function mac(secret, f) {
    const message = `mont-approval:v1:${f.id}:${f.decision}:${f.exp}:${f.queuedAt}`;
    return crypto_1.default.createHmac("sha256", Buffer.from(secret, "hex")).update(message, "utf8").digest();
}
function signApprovalLink(secret, fields) {
    return mac(secret, fields).toString("base64url");
}
function verifyApprovalLink(secret, fields, signature, now = Date.now()) {
    if (
    // id 0 is the Setup tab's test notification: it verifies but never matches an action.
    !Number.isInteger(fields.id) ||
        fields.id < 0 ||
        (fields.decision !== "APPROVE" && fields.decision !== "REJECT") ||
        !Number.isInteger(fields.exp) ||
        typeof signature !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(signature)) {
        return { ok: false, reason: "malformed" };
    }
    const expected = mac(secret, fields);
    const supplied = Buffer.from(signature, "base64url");
    // Reject non-canonical encodings (the last base64 char carries 2 padding bits), so each MAC has exactly one valid spelling.
    if (supplied.toString("base64url") !== signature)
        return { ok: false, reason: "malformed" };
    // Check the signature before the expiry so a forged link never learns anything from timing or messages.
    if (supplied.length !== expected.length || !crypto_1.default.timingSafeEqual(supplied, expected)) {
        return { ok: false, reason: "bad_signature" };
    }
    if (fields.exp <= now)
        return { ok: false, reason: "expired" };
    return { ok: true };
}
function parseCallbackDecision(value) {
    if (value === "APPROVE" || value === "REJECT")
        return value;
    return null;
}
// ---------------------------------------------------------------------------
// In-chat button tokens (Telegram callback_data / Slack button value).
// Format: "mont:<A|R>:<id>:<mac>" where mac = first 22 base64url chars (132 bits) of
// HMAC-SHA256(secret, "mont-button:v1:<id>:<decision>:<queuedAt>"). At most ~45 bytes,
// inside Telegram's 64-byte callback_data limit. Bound to the exact queued row.
// ---------------------------------------------------------------------------
const BUTTON_MAC_CHARS = 22;
function buttonMac(secret, id, decision, queuedAt) {
    return crypto_1.default
        .createHmac("sha256", Buffer.from(secret, "hex"))
        .update(`mont-button:v1:${id}:${decision}:${queuedAt}`, "utf8")
        .digest("base64url")
        .slice(0, BUTTON_MAC_CHARS);
}
function signButtonToken(secret, id, decision, queuedAt) {
    return `mont:${decision === "APPROVE" ? "A" : "R"}:${id}:${buttonMac(secret, id, decision, queuedAt)}`;
}
/** Parses a token without trusting it. Verify with verifyButtonToken once the row's queuedAt is known. */
function parseButtonToken(token) {
    if (typeof token !== "string")
        return null;
    const m = /^mont:([AR]):(\d{1,10}):([A-Za-z0-9_-]{22})$/.exec(token);
    if (!m)
        return null;
    const id = Number(m[2]);
    if (!Number.isSafeInteger(id) || id < 1)
        return null;
    return { id, decision: m[1] === "A" ? "APPROVE" : "REJECT", mac: m[3] };
}
function verifyButtonToken(secret, parsed, queuedAt) {
    const expected = Buffer.from(buttonMac(secret, parsed.id, parsed.decision, queuedAt));
    const supplied = Buffer.from(parsed.mac);
    return supplied.length === expected.length && crypto_1.default.timingSafeEqual(supplied, expected);
}
/** Full confirmation URL, e.g. https://gw.example.com/_mont/approvals/12/confirm?d=APPROVE&exp=...&sig=... */
function buildApprovalLink(publicBaseUrl, secret, fields) {
    const base = publicBaseUrl.replace(/\/+$/, "");
    const sig = signApprovalLink(secret, fields);
    const params = new URLSearchParams({ d: fields.decision, exp: String(fields.exp), sig });
    return `${base}${constants_1.APPROVAL_CALLBACK_PREFIX}/${fields.id}/confirm?${params.toString()}`;
}
