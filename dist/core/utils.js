"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_RULE_RATE_LIMIT = exports.PRO_REQUIRED_MESSAGE = exports.UPGRADE_URL = void 0;
exports.sendError = sendError;
exports.sendProRequired = sendProRequired;
exports.sendCaughtError = sendCaughtError;
exports.sendInternalError = sendInternalError;
exports.normalizePath = normalizePath;
exports.writeJsonAtomic = writeJsonAtomic;
exports.parseJsonObject = parseJsonObject;
exports.parseTargetUrl = parseTargetUrl;
exports.validateRulePath = validateRulePath;
exports.redactSensitive = redactSensitive;
exports.ruleKey = ruleKey;
exports.parseRuleKey = parseRuleKey;
exports.redactQueryString = redactQueryString;
exports.isValidRuleRateLimit = isValidRuleRateLimit;
exports.normalizeRule = normalizeRule;
exports.extractBody = extractBody;
exports.extractRedactedBody = extractRedactedBody;
exports.sanitizeHeaders = sanitizeHeaders;
exports.escapeLike = escapeLike;
exports.truncate = truncate;
const fs_1 = __importDefault(require("fs"));
const constants_1 = require("./constants");
const crypto_1 = require("./crypto");
function sendError(res, status, error, message, extra) {
    res.status(status).json({ error, message, ...extra });
}
exports.UPGRADE_URL = "https://montweel.com/#license-renewal";
exports.PRO_REQUIRED_MESSAGE = "Pro feature — claim your free 90-day trial key (no payment card required) or upgrade at https://montweel.com";
/**
 * Team Pro gate. Deliberately NOT an error status: replies 200 with `proRequired: true` so
 * clients can show an upgrade prompt instead of a failure. `feature` is kept for call-site clarity.
 */
function sendProRequired(res, _feature) {
    res.status(200).json({ proRequired: true, message: exports.PRO_REQUIRED_MESSAGE, upgradeUrl: exports.UPGRADE_URL });
}
function sendCaughtError(res, err) {
    if (res.headersSent)
        return;
    const e = err;
    const status = typeof e?.status === "number" && e.status >= 400 && e.status < 500 ? e.status : 500;
    if (status === 500) {
        console.error("Unhandled error:", err);
        sendError(res, 500, "Internal Server Error", "Unexpected error.");
        return;
    }
    const names = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        408: "Request Timeout",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        429: "Too Many Requests",
    };
    sendError(res, status, names[status] ?? "Bad Request", typeof e?.message === "string" ? e.message : "Invalid request.");
}
/** Logs the real error server-side and sends a generic message to the client. */
function sendInternalError(res, context, err, clientMessage) {
    if (err instanceof crypto_1.ScryptBusyError) {
        if (!res.headersSent) {
            res.setHeader("Retry-After", "2");
            sendError(res, 429, "Too Many Requests", err.message);
        }
        return;
    }
    console.error(`${context}:`, err);
    if (!res.headersSent)
        sendError(res, 500, "Internal Server Error", clientMessage);
}
function normalizePath(p) {
    return p.length > 1 ? p.replace(/\/+$/, "") : p;
}
// Files may hold secrets (config.json can contain static tokens), so keep them owner-only.
function writeJsonAtomic(filePath, data) {
    const tmpPath = filePath + ".tmp";
    fs_1.default.writeFileSync(tmpPath, JSON.stringify(data, null, 2), { encoding: "utf-8", mode: 0o600 });
    fs_1.default.renameSync(tmpPath, filePath);
}
function parseJsonObject(text) {
    if (!text)
        return {};
    try {
        const parsed = JSON.parse(text);
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
            return parsed;
        }
    }
    catch {
        // ignore bad JSON
    }
    return {};
}
const BLOCKED_TARGET_HOSTS = new Set([
    "169.254.169.254", // AWS / Azure / GCP instance metadata
    "metadata.google.internal",
    "100.100.100.200", // Alibaba Cloud metadata
    "fd00:ec2::254", // AWS IPv6 metadata
]);
function parseTargetUrl(value, gatewayPort) {
    const trimmed = value.trim().replace(/\/+$/, "");
    if (trimmed === "")
        return { ok: true, url: "" };
    let parsed;
    try {
        parsed = new URL(trimmed);
    }
    catch {
        return { ok: false, message: "targetUrl must be a full URL like https://api.example.com" };
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return { ok: false, message: "targetUrl must start with http:// or https://" };
    }
    if (parsed.username || parsed.password) {
        return { ok: false, message: "targetUrl must not contain embedded credentials." };
    }
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (BLOCKED_TARGET_HOSTS.has(hostname) || hostname.startsWith("169.254.")) {
        return { ok: false, message: "targetUrl cannot point at a cloud metadata / link-local address." };
    }
    const urlPort = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
    const localHosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
    if (localHosts.includes(hostname) && urlPort === String(gatewayPort)) {
        return {
            ok: false,
            message: `targetUrl cannot point at this gateway itself (localhost:${gatewayPort}).`,
        };
    }
    return { ok: true, url: trimmed };
}
/**
 * Returns an error message when a rule path is unsafe, or null when it is fine.
 * Rules match the request path byte-for-byte, so anything ambiguous is refused:
 * traversal ("..", encoded dots/slashes), whitespace, control characters, "\\".
 */
function validateRulePath(endpoint) {
    if (!endpoint.startsWith("/api/"))
        return 'Endpoints must start with "/api/".';
    if (endpoint.length > constants_1.MAX_RULE_PATH_LENGTH)
        return `Endpoints must be ${constants_1.MAX_RULE_PATH_LENGTH} characters or fewer.`;
    if (endpoint.includes(".."))
        return 'Endpoints cannot contain "..".';
    if (/\s/.test(endpoint))
        return "Endpoints cannot contain whitespace.";
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(endpoint))
        return "Endpoints cannot contain control characters.";
    if (endpoint.includes("\\") || /%2e|%2f|%5c|%00/i.test(endpoint)) {
        return "Endpoints cannot contain backslashes or encoded dots, slashes or null bytes.";
    }
    if (endpoint.includes("?") || endpoint.includes("#")) {
        return "Leave out query strings; rules match the path only.";
    }
    return null;
}
function isSensitiveKey(key) {
    const k = key.toLowerCase().replace(/[_-]/g, "");
    return constants_1.SENSITIVE_KEYS.some((s) => k.includes(s));
}
/** Deep copy of a parsed JSON value with sensitive keys replaced by "[REDACTED]". */
function redactSensitive(value, depth = 0) {
    if (depth > 20)
        return constants_1.REDACTED; // absurdly deep: do not risk leaking something below
    if (Array.isArray(value))
        return value.map((v) => redactSensitive(v, depth + 1));
    if (typeof value === "object" && value !== null) {
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[k] = isSensitiveKey(k) ? constants_1.REDACTED : redactSensitive(v, depth + 1);
        }
        return out;
    }
    return value;
}
/** Rule key for a method-specific rule, e.g. "POST /api/flights". */
function ruleKey(method, endpoint) {
    return method ? `${method} ${endpoint}` : endpoint;
}
/**
 * Splits a rule key into its method (null = any method) and path. Accepts
 * "/api/x" and "POST /api/x" (method case-insensitive, "ANY /api/x" = "/api/x").
 * Returns an error message when the key is unusable. The returned `path` still
 * needs validateRulePath().
 */
function parseRuleKey(raw) {
    const trimmed = raw.trim();
    const space = trimmed.search(/\s/);
    if (space === -1)
        return { method: null, path: normalizePath(trimmed) };
    const word = trimmed.slice(0, space).toUpperCase();
    const rest = trimmed.slice(space).trim();
    if (word === "ANY")
        return { method: null, path: normalizePath(rest) };
    if (!constants_1.RULE_METHODS.includes(word)) {
        return { error: `Unknown method "${trimmed.slice(0, space)}". Use ${constants_1.RULE_METHODS.slice(0, 5).join(", ")} or leave the method out.` };
    }
    return { method: word, path: normalizePath(rest) };
}
/** Replaces the values of sensitive query parameters, leaving everything else byte-for-byte. */
function redactQueryString(url) {
    const q = url.indexOf("?");
    if (q === -1)
        return url;
    const hash = url.indexOf("#", q);
    const queryEnd = hash === -1 ? url.length : hash;
    const query = url.slice(q + 1, queryEnd);
    const redacted = query
        .split("&")
        .map((pair) => {
        const eq = pair.indexOf("=");
        if (eq === -1)
            return pair;
        let name = pair.slice(0, eq);
        try {
            name = decodeURIComponent(name.replace(/\+/g, " "));
        }
        catch {
            // keep the raw name
        }
        const k = name.toLowerCase().replace(/[_-]/g, "");
        const sensitive = constants_1.SENSITIVE_QUERY_KEYS.some((s) => k === s || k.endsWith(s));
        return sensitive ? `${pair.slice(0, eq)}=${encodeURIComponent(constants_1.REDACTED)}` : pair;
    })
        .join("&");
    return url.slice(0, q + 1) + redacted + url.slice(queryEnd);
}
exports.MAX_RULE_RATE_LIMIT = 1000000;
function isValidRuleRateLimit(n) {
    return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= exports.MAX_RULE_RATE_LIMIT;
}
function normalizeRule(value) {
    if (value === true)
        return { mode: "ALLOW", description: "" };
    if (value === false)
        return { mode: "BLOCK", description: "" };
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
        const v = value;
        const mode = typeof v.mode === "string" && constants_1.RULE_MODES.includes(v.mode)
            ? v.mode
            : "BLOCK";
        const rule = { mode, description: typeof v.description === "string" ? v.description : "" };
        if (isValidRuleRateLimit(v.rateLimit))
            rule.rateLimit = v.rateLimit;
        return rule;
    }
    return null;
}
function extractBody(req) {
    if (constants_1.NO_BODY_METHODS.includes(req.method))
        return null;
    const body = req.body;
    if (body === undefined || body === null)
        return null;
    if (typeof body === "object" && Object.keys(body).length === 0) {
        return req.is("application/json") ? "{}" : null;
    }
    return JSON.stringify(body);
}
/** Like extractBody, but safe to store: sensitive JSON values are redacted. */
function extractRedactedBody(req) {
    if (constants_1.NO_BODY_METHODS.includes(req.method))
        return null;
    const body = req.body;
    if (body === undefined || body === null)
        return null;
    if (typeof body === "object" && Object.keys(body).length === 0) {
        return req.is("application/json") ? "{}" : null;
    }
    return JSON.stringify(redactSensitive(body));
}
function sanitizeHeaders(req) {
    const out = {};
    for (const [key, value] of Object.entries(req.headers)) {
        const k = key.toLowerCase();
        if (value === undefined || constants_1.UNSAVED_HEADERS.has(k))
            continue;
        out[k] = Array.isArray(value) ? value.join(", ") : value;
    }
    return out;
}
/** Escapes % _ \ so user input is matched literally inside a LIKE ... ESCAPE '\' clause. */
function escapeLike(input) {
    return input.replace(/[\\%_]/g, (c) => `\\${c}`);
}
function truncate(value, max) {
    return value.length > max ? value.slice(0, max) : value;
}
