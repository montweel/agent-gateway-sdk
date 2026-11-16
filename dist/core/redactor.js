"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeRedactKey = exports.REDACTED_SECRET = exports.REDACTED_CARD = exports.REDACTED = void 0;
exports.luhnValid = luhnValid;
exports.looksLikeCard = looksLikeCard;
exports.scrubSecrets = scrubSecrets;
exports.isSecretKey = isSecretKey;
exports.createRedactor = createRedactor;
exports.REDACTED = "[REDACTED]";
exports.REDACTED_CARD = "[REDACTED:card]";
exports.REDACTED_SECRET = "[REDACTED:secret]";
const MAX_DEPTH = 20;
// Matched after lower-casing and removing "_", "-" and ".".
const SECRET_KEY_SUBSTRINGS = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "cookie",
    "cvv",
    "cvc",
    "cardnumber",
    "creditcard",
    "privatekey",
    "accesskey",
    "sessionid",
    "signature",
];
const SECRET_KEY_EXACT = new Set(["pin", "ssn", "pan", "auth", "otp", "card"]);
const EMAIL_KEY = /^(?:mail|.*email.*)$/;
const PHONE_KEY_SUBSTRINGS = ["phone", "mobile", "msisdn", "whatsapp", "cellnumber", "telephone"];
const PHONE_KEY_EXACT = new Set(["tel", "cell", "fax"]);
const SECRET_HEADERS = new Set([
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-agent-key",
    "x-admin-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-gateway-sso-secret",
    "x-gateway-internal-replay",
    "x-setup-token",
]);
const DROPPED_HEADERS = new Set(["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "content-length"]);
const SECRET_PATTERNS = [
    /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/gi,
    /\bBasic\s+[A-Za-z0-9+/]{8,}=*/g,
    /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, // JWT
    /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, // Stripe secret / restricted keys
    /\bwhsec_[A-Za-z0-9]{16,}/g, // Stripe webhook secrets
    /\bgh[pousr]_[A-Za-z0-9]{20,}/g, // GitHub tokens
    /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
    /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, // Slack tokens
    /\bxapp-[A-Za-z0-9-]{10,}/g,
    /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
    // Telegram bot token, bare or inside an API URL (".../bot123456789:AA.../sendMessage", where a
    // plain \b before the digits would not match).
    /(?:\bbot|\b)\d{6,12}:[A-Za-z0-9_-]{30,}/g,
    // Slack incoming-webhook / workflow URLs: the path IS the credential.
    /https?:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/gi,
    /\bagk_[A-Za-z0-9]{8,}/g, // Mont agent keys
    /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/g, // OpenAI / Anthropic style keys
];
// 13-19 digits, optionally grouped with single spaces or dashes.
const CARD_CANDIDATE = /(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])/g;
const EMAIL_VALUE = /([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/g;
// The same address percent-encoded inside a URL (jane%40example.com).
const EMAIL_VALUE_ENCODED = /([A-Za-z0-9._+-])[A-Za-z0-9._+-]*%40([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/gi;
// International-format numbers: a "+" then 8-15 digits with optional separators.
const PHONE_VALUE = /(?<![\w+])\+\d(?:[\s().-]?\d){7,14}(?!\d)/g;
function luhnValid(digits) {
    if (!/^\d{13,19}$/.test(digits))
        return false;
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let d = digits.charCodeAt(i) - 48;
        if (double) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
        double = !double;
    }
    return sum % 10 === 0;
}
/** Luhn-valid AND starts with a real card network prefix (2-6), so ms timestamps (1…) never match. */
function looksLikeCard(digits) {
    return /^[2-6]/.test(digits) && luhnValid(digits);
}
/**
 * Secrets and card numbers only (no email / phone masking): what the outbound response guard
 * treats as "must never leave". Returns the masked text and how many values were masked.
 */
function scrubSecrets(value) {
    let hits = 0;
    let out = value;
    for (const re of SECRET_PATTERNS) {
        out = out.replace(re, () => {
            hits++;
            return exports.REDACTED_SECRET;
        });
    }
    out = out.replace(CARD_CANDIDATE, (m) => {
        if (!looksLikeCard(m.replace(/[ -]/g, "")))
            return m;
        hits++;
        return exports.REDACTED_CARD;
    });
    return { text: out, hits };
}
function normKey(key) {
    return key.toLowerCase().replace(/[_\-.\s]/g, "");
}
function isSecretKey(key) {
    const k = normKey(key);
    return SECRET_KEY_EXACT.has(k) || SECRET_KEY_SUBSTRINGS.some((s) => k.includes(s));
}
/** The form a configured redact key is compared in (config.json audit.redactKeys). */
exports.normalizeRedactKey = normKey;
const NO_EXTRA_KEYS = new Set();
function isEmailKey(key) {
    return EMAIL_KEY.test(normKey(key));
}
function isPhoneKey(key) {
    const k = normKey(key);
    return PHONE_KEY_EXACT.has(k) || PHONE_KEY_SUBSTRINGS.some((s) => k.includes(s));
}
function maskPhone(value) {
    const digits = value.replace(/\D/g, "");
    return digits.length >= 4 ? `[REDACTED:phone ••${digits.slice(-2)}]` : "[REDACTED:phone]";
}
/**
 * `extraKeys` returns the configured redact keys, already normalised (normalizeRedactKey). They are
 * matched against whole keys, in addition to the built-in list. Read once per json() / jsonText() call.
 */
function createRedactor(options, extraKeys = () => NO_EXTRA_KEYS) {
    const secretKey = (key, extra) => isSecretKey(key) || (extra.size > 0 && extra.has(normKey(key)));
    function text(value) {
        const opts = options();
        let out = value;
        for (const re of SECRET_PATTERNS)
            out = out.replace(re, exports.REDACTED_SECRET);
        out = out.replace(CARD_CANDIDATE, (m) => (looksLikeCard(m.replace(/[ -]/g, "")) ? exports.REDACTED_CARD : m));
        if (opts.redactEmails) {
            out = out.replace(EMAIL_VALUE, (_m, first, domain) => `${first}***@${domain}`);
            out = out.replace(EMAIL_VALUE_ENCODED, (_m, first, domain) => `${first}***%40${domain}`);
        }
        if (opts.redactPhones)
            out = out.replace(PHONE_VALUE, (m) => maskPhone(m));
        return out;
    }
    function scalar(value, key, extra) {
        const opts = options();
        if (key !== null) {
            if (secretKey(key, extra))
                return value === null || value === "" ? value : exports.REDACTED;
            if (opts.redactPhones && isPhoneKey(key) && (typeof value === "string" || typeof value === "number")) {
                return maskPhone(String(value));
            }
            if (opts.redactEmails && isEmailKey(key) && typeof value === "string" && !value.includes("@")) {
                // An "email" field that is not an address still is the customer's identifier; keep it masked.
                return value === "" ? value : exports.REDACTED;
            }
        }
        if (typeof value === "string")
            return text(value);
        if (typeof value === "number" && Number.isSafeInteger(value) && looksLikeCard(String(Math.abs(value))))
            return exports.REDACTED_CARD;
        return value;
    }
    function walk(value, key, depth, extra) {
        if (depth > MAX_DEPTH)
            return exports.REDACTED;
        if (Array.isArray(value)) {
            if (key !== null && secretKey(key, extra))
                return exports.REDACTED;
            return value.map((v) => walk(v, key, depth + 1, extra));
        }
        if (typeof value === "object" && value !== null) {
            if (key !== null && secretKey(key, extra))
                return exports.REDACTED;
            const out = {};
            for (const [k, v] of Object.entries(value))
                out[k] = walk(v, k, depth + 1, extra);
            return out;
        }
        return scalar(value, key, extra);
    }
    function headers(h) {
        const extra = extraKeys();
        const out = {};
        for (const [rawKey, v] of Object.entries(h)) {
            if (v === undefined)
                continue;
            const k = rawKey.toLowerCase();
            if (DROPPED_HEADERS.has(k))
                continue;
            const value = Array.isArray(v) ? v.join(", ") : v;
            out[k] = SECRET_HEADERS.has(k) || secretKey(k, extra) ? exports.REDACTED : text(value);
        }
        return out;
    }
    function jsonText(t) {
        if (t === null)
            return null;
        let parsed;
        try {
            parsed = JSON.parse(t);
        }
        catch {
            return text(t);
        }
        return JSON.stringify(walk(parsed, null, 0, extraKeys()));
    }
    return { json: (v) => walk(v, null, 0, extraKeys()), text, headers, jsonText };
}
