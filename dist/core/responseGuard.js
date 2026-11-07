"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.inspectJsonValue = inspectJsonValue;
exports.inspectResponseBody = inspectResponseBody;
exports.inspectValue = inspectValue;
exports.inspectMcpResult = inspectMcpResult;
exports.describeFindings = describeFindings;
exports.validateResponseGuard = validateResponseGuard;
const redactor_1 = require("./redactor");
const MAX_FINDINGS = 50;
const PAGINATION_KEY = /page|cursor|continuation/i;
const MAX_DEPTH = 64;
/** Walks a parsed JSON value. Mutates nothing: returns a new value when something changed. */
function inspectJsonValue(value, opts) {
    const findings = [];
    let changed = false;
    const note = (f) => {
        if (findings.length < MAX_FINDINGS)
            findings.push(f);
    };
    function walk(v, path, key, depth) {
        if (depth > MAX_DEPTH)
            return v;
        if (Array.isArray(v)) {
            let arr = v;
            if (arr.length > opts.maxArrayItems) {
                note({ kind: "large_array", path, count: arr.length });
                if (opts.onLargeArray === "truncate") {
                    arr = arr.slice(0, opts.maxArrayItems);
                    changed = true;
                }
            }
            let local = false;
            const out = arr.map((item, i) => {
                const next = walk(item, `${path}[${i}]`, key, depth + 1);
                if (next !== item)
                    local = true;
                return next;
            });
            return local || arr !== v ? out : v;
        }
        if (typeof v === "object" && v !== null) {
            let local = false;
            const out = {};
            for (const [k, child] of Object.entries(v)) {
                const next = walk(child, `${path}.${k}`, k, depth + 1);
                if (next !== child)
                    local = true;
                out[k] = next;
            }
            return local ? out : v;
        }
        if (typeof v === "string") {
            // A secret-looking key holding a credential-sized string (pagination cursors excepted:
            // "next_page_token" is not a credential and masking it would break paging).
            if (key !== null && (0, redactor_1.isSecretKey)(key) && !PAGINATION_KEY.test(key) && v.length >= 8) {
                note({ kind: "secret", path, count: 1 });
                changed = true;
                return redactor_1.REDACTED;
            }
            const s = (0, redactor_1.scrubSecrets)(v);
            if (s.hits > 0) {
                note({ kind: "secret", path, count: s.hits });
                changed = true;
                return s.text;
            }
            return v;
        }
        if (typeof v === "number" && Number.isSafeInteger(v) && (0, redactor_1.looksLikeCard)(String(Math.abs(v)))) {
            note({ kind: "secret", path, count: 1 });
            changed = true;
            return redactor_1.REDACTED;
        }
        return v;
    }
    const out = walk(value, "$", null, 0);
    return { value: out, findings, changed };
}
function decide(findings, settings) {
    const largeArray = findings.some((f) => f.kind === "large_array");
    const secret = findings.some((f) => f.kind === "secret");
    if (largeArray && settings.onLargeArray === "block")
        return "block";
    if (secret && settings.onSecret === "block")
        return "block";
    return "modify";
}
const isJsonType = (ct) => /^application\/(?:[\w.+-]+\+)?json\b/i.test(ct) || /^application\/json/i.test(ct);
const isTextType = (ct) => /^text\//i.test(ct) && !/^text\/event-stream/i.test(ct);
/** Inspects an HTTP response body (already fully buffered and decompressed). */
function inspectResponseBody(contentType, body, settings) {
    if (!settings.enabled || body.length === 0)
        return { action: "pass", findings: [] };
    const ct = (contentType ?? "").toLowerCase();
    if (isJsonType(ct)) {
        let parsed;
        try {
            parsed = JSON.parse(body.toString("utf8"));
        }
        catch {
            return inspectText(body, settings); // claims JSON but is not: still scan it for secrets
        }
        const r = inspectJsonValue(parsed, settings);
        if (r.findings.length === 0)
            return { action: "pass", findings: [] };
        if (decide(r.findings, settings) === "block")
            return { action: "block", findings: r.findings };
        return { action: "modified", findings: r.findings, body: Buffer.from(JSON.stringify(r.value), "utf8") };
    }
    if (isTextType(ct))
        return inspectText(body, settings);
    return { action: "pass", findings: [] };
}
function inspectText(body, settings) {
    const s = (0, redactor_1.scrubSecrets)(body.toString("utf8"));
    if (s.hits === 0)
        return { action: "pass", findings: [] };
    const findings = [{ kind: "secret", path: "$", count: s.hits }];
    if (settings.onSecret === "block")
        return { action: "block", findings };
    return { action: "modified", findings, body: Buffer.from(s.text, "utf8") };
}
/** Inspects a JSON value (an MCP tool result). */
function inspectValue(value, settings) {
    if (!settings.enabled)
        return { action: "pass", findings: [], value };
    const r = inspectJsonValue(value, settings);
    if (r.findings.length === 0)
        return { action: "pass", findings: [], value };
    // JSON-encoded text inside MCP content blocks ({ type: "text", text: "[{...}, ...]" }) is checked too.
    if (decide(r.findings, settings) === "block")
        return { action: "block", findings: r.findings, value };
    return { action: "modified", findings: r.findings, value: r.value };
}
/**
 * MCP tool results usually carry their data as JSON text inside content blocks. Parses those
 * (when they are JSON) so a 1,000-row dump inside a text block is seen as an array too.
 */
function inspectMcpResult(result, settings) {
    if (!settings.enabled || typeof result !== "object" || result === null)
        return { action: "pass", findings: [], result };
    const r = result;
    const findings = [];
    let changed = false;
    let blocked = false;
    const next = { ...r };
    if (Array.isArray(r.content)) {
        next.content = r.content.map((block, i) => {
            if (typeof block !== "object" || block === null)
                return block;
            const b = block;
            if (b.type !== "text" || typeof b.text !== "string") {
                const v = inspectValue(b, settings);
                findings.push(...v.findings.map((f) => ({ ...f, path: f.path.replace(/^\$/, `$.content[${i}]`) })));
                if (v.action === "block")
                    blocked = true;
                if (v.action === "modified") {
                    changed = true;
                    return v.value;
                }
                return block;
            }
            let parsed;
            let isJson = false;
            const trimmed = b.text.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                try {
                    parsed = JSON.parse(trimmed);
                    isJson = true;
                }
                catch {
                    isJson = false;
                }
            }
            if (isJson) {
                const v = inspectValue(parsed, settings);
                findings.push(...v.findings.map((f) => ({ ...f, path: f.path.replace(/^\$/, `$.content[${i}].text`) })));
                if (v.action === "block")
                    blocked = true;
                if (v.action === "modified") {
                    changed = true;
                    return { ...b, text: JSON.stringify(v.value) };
                }
                return block;
            }
            const s = (0, redactor_1.scrubSecrets)(b.text);
            if (s.hits > 0) {
                findings.push({ kind: "secret", path: `$.content[${i}].text`, count: s.hits });
                if (settings.onSecret === "block")
                    blocked = true;
                changed = true;
                return { ...b, text: s.text };
            }
            return block;
        });
    }
    if (r.structuredContent !== undefined) {
        const v = inspectValue(r.structuredContent, settings);
        findings.push(...v.findings.map((f) => ({ ...f, path: f.path.replace(/^\$/, "$.structuredContent") })));
        if (v.action === "block")
            blocked = true;
        if (v.action === "modified") {
            changed = true;
            next.structuredContent = v.value;
        }
    }
    if (findings.length === 0)
        return { action: "pass", findings: [], result };
    if (blocked)
        return { action: "block", findings, result };
    return { action: changed ? "modified" : "pass", findings, result: changed ? next : result };
}
function describeFindings(findings) {
    const arrays = findings.filter((f) => f.kind === "large_array");
    const secrets = findings.filter((f) => f.kind === "secret");
    const parts = [];
    if (arrays.length)
        parts.push(`bulk data (${arrays.map((a) => `${a.path}: ${a.count} items`).slice(0, 3).join(", ")})`);
    if (secrets.length)
        parts.push(`${secrets.reduce((n, s) => n + s.count, 0)} secret value(s) (${secrets.map((s) => s.path).slice(0, 3).join(", ")})`);
    return parts.join("; ");
}
function validateResponseGuard(raw, current) {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw))
        return { ok: false, message: "responseGuard must be an object." };
    const r = raw;
    const next = { ...current };
    if (r.enabled !== undefined) {
        if (typeof r.enabled !== "boolean")
            return { ok: false, message: "responseGuard.enabled must be true or false." };
        next.enabled = r.enabled;
    }
    if (r.maxArrayItems !== undefined) {
        if (!Number.isInteger(r.maxArrayItems) || r.maxArrayItems < 1 || r.maxArrayItems > 1000000) {
            return { ok: false, message: "responseGuard.maxArrayItems must be a whole number from 1 to 1,000,000." };
        }
        next.maxArrayItems = r.maxArrayItems;
    }
    if (r.onLargeArray !== undefined) {
        if (r.onLargeArray !== "block" && r.onLargeArray !== "truncate")
            return { ok: false, message: 'responseGuard.onLargeArray must be "block" or "truncate".' };
        next.onLargeArray = r.onLargeArray;
    }
    if (r.onSecret !== undefined) {
        if (r.onSecret !== "scrub" && r.onSecret !== "block")
            return { ok: false, message: 'responseGuard.onSecret must be "scrub" or "block".' };
        next.onSecret = r.onSecret;
    }
    return { ok: true, value: next };
}
