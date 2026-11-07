"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_POLICY_STRING = exports.MAX_IN_VALUES = exports.MAX_REGEX_INPUT = exports.MAX_REGEX_LENGTH = exports.MAX_POLICY_PATH_DEPTH = exports.MAX_POLICY_FIELD_LENGTH = exports.MAX_POLICY_CONDITIONS = exports.MAX_POLICY_TIERS = exports.POLICY_ROOTS = exports.POLICY_OPERATORS = void 0;
exports.parseFieldPath = parseFieldPath;
exports.resolveField = resolveField;
exports.evaluateCondition = evaluateCondition;
exports.evaluateRule = evaluateRule;
exports.policiesReadBody = policiesReadBody;
exports.validatePolicies = validatePolicies;
exports.normalizePolicies = normalizePolicies;
exports.validateBudget = validateBudget;
exports.validateDedupe = validateDedupe;
const constants_1 = require("./constants");
/**
 * Deterministic payload policy engine.
 *
 * A rule can carry ordered tiers. Each tier is a list of conditions that must ALL hold;
 * the first tier that matches decides the mode. When no tier matches, the rule's own
 * `mode` applies. Example for POST /api/refund:
 *
 *   { "mode": "REQUIRE_APPROVAL", "policies": [
 *       { "name": "small",  "when": [{ "field": "body.amount", "op": "<=", "value": 100 }],  "mode": "ALLOW" },
 *       { "name": "huge",   "when": [{ "field": "body.amount", "op": ">",  "value": 1000 }], "mode": "BLOCK" } ] }
 *
 * Fail-closed guarantees:
 *   - A field that is missing, or has the wrong type for the operator, makes that condition
 *     false (only "exists" looks at presence). A tier can therefore never ALLOW by accident.
 *   - Body values are never coerced: "amount": "50" is a string and does not satisfy <= 100.
 *   - Any unexpected evaluation error yields BLOCK.
 *   - rules.json entries whose policies fail validation are loaded as BLOCK (see normalizePolicies).
 */
exports.POLICY_OPERATORS = [">", "<", ">=", "<=", "===", "!==", "contains", "in", "regex", "exists"];
exports.POLICY_ROOTS = ["body", "query", "headers"];
exports.MAX_POLICY_TIERS = 20;
exports.MAX_POLICY_CONDITIONS = 10;
exports.MAX_POLICY_FIELD_LENGTH = 200;
exports.MAX_POLICY_PATH_DEPTH = 12;
exports.MAX_REGEX_LENGTH = 256;
exports.MAX_REGEX_INPUT = 4096;
exports.MAX_IN_VALUES = 100;
exports.MAX_POLICY_STRING = 1000;
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);
const NUMERIC_STRING = /^-?(?:0|[1-9]\d{0,15})(?:\.\d{1,15})?$/;
// Nested quantifiers such as (a+)+ or (a*)* are the classic catastrophic-backtracking shapes.
const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]/;
function isPrimitive(v) {
    return v === null || typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}
function own(obj, key) {
    return Object.prototype.hasOwnProperty.call(obj, key);
}
/** Splits "body.items.0.price" into ["body", "items", "0", "price"], or returns an error. */
function parseFieldPath(field) {
    if (typeof field !== "string" || field.trim() === "")
        return { error: "field must be a non-empty string." };
    if (field.length > exports.MAX_POLICY_FIELD_LENGTH)
        return { error: `field must be ${exports.MAX_POLICY_FIELD_LENGTH} characters or fewer.` };
    const parts = field.trim().split(".");
    const root = parts[0];
    if (!exports.POLICY_ROOTS.includes(root))
        return { error: 'field must start with "body.", "query." or "headers."' };
    const segments = parts.slice(1);
    if (segments.length === 0)
        return { error: `field "${field}" needs a key after "${root}."` };
    if (segments.length > exports.MAX_POLICY_PATH_DEPTH)
        return { error: `field "${field}" is nested too deeply.` };
    for (const s of segments) {
        if (s === "")
            return { error: `field "${field}" has an empty segment.` };
        if (FORBIDDEN_SEGMENTS.has(s))
            return { error: `field "${field}" uses a reserved key.` };
    }
    return { root, segments: root === "headers" ? segments.map((s) => s.toLowerCase()) : segments };
}
/** Resolves a field against the request. Own properties only; arrays accept numeric indexes. */
function resolveField(input, field) {
    const parsed = parseFieldPath(field);
    if ("error" in parsed)
        return { found: false, value: undefined, root: null };
    let current;
    if (parsed.root === "headers") {
        // Header names may contain dots in theory; join the rest so "headers.x-agent-reason" works.
        const name = parsed.segments.join(".");
        const raw = input.headers[name];
        if (raw === undefined)
            return { found: false, value: undefined, root: "headers" };
        return { found: true, value: Array.isArray(raw) ? raw.join(", ") : raw, root: "headers" };
    }
    current = parsed.root === "body" ? input.body : input.query;
    for (const seg of parsed.segments) {
        if (Array.isArray(current)) {
            if (!/^\d{1,6}$/.test(seg))
                return { found: false, value: undefined, root: parsed.root };
            const idx = Number(seg);
            if (idx >= current.length)
                return { found: false, value: undefined, root: parsed.root };
            current = current[idx];
        }
        else if (typeof current === "object" && current !== null) {
            if (!own(current, seg))
                return { found: false, value: undefined, root: parsed.root };
            current = current[seg];
        }
        else {
            return { found: false, value: undefined, root: parsed.root };
        }
    }
    return { found: current !== undefined, value: current, root: parsed.root };
}
/** Numbers for comparison. Body: real JSON numbers only. Query/headers: canonical decimal strings. */
function asNumber(value, root) {
    if (typeof value === "number")
        return Number.isFinite(value) ? value : null;
    if ((root === "query" || root === "headers") && typeof value === "string" && NUMERIC_STRING.test(value)) {
        const n = Number(value);
        return Number.isFinite(n) ? n : null;
    }
    return null;
}
/** Equality used by === !== and in. Strict, except that a query/header string may equal a number. */
function primitiveEquals(actual, expected, root) {
    if (!isPrimitive(actual))
        return false;
    if (actual === expected)
        return true;
    if (typeof expected === "number" && (root === "query" || root === "headers")) {
        const n = asNumber(actual, root);
        return n !== null && n === expected;
    }
    if (typeof expected === "boolean" && (root === "query" || root === "headers") && typeof actual === "string") {
        return actual === String(expected);
    }
    return false;
}
const regexCache = new Map();
function compileRegex(pattern, flags) {
    const f = flags === "i" ? "i" : "";
    const key = `${f}/${pattern}`;
    let re = regexCache.get(key);
    if (!re) {
        re = new RegExp(pattern, f);
        if (regexCache.size > 1000)
            regexCache.clear();
        regexCache.set(key, re);
    }
    return re;
}
function evaluateCondition(cond, input) {
    const { found, value, root } = resolveField(input, cond.field);
    if (cond.op === "exists") {
        const want = cond.value === undefined ? true : cond.value === true;
        return found === want;
    }
    if (!found)
        return false;
    switch (cond.op) {
        case ">":
        case "<":
        case ">=":
        case "<=": {
            const a = asNumber(value, root);
            const b = typeof cond.value === "number" && Number.isFinite(cond.value) ? cond.value : null;
            if (a === null || b === null)
                return false;
            if (cond.op === ">")
                return a > b;
            if (cond.op === "<")
                return a < b;
            if (cond.op === ">=")
                return a >= b;
            return a <= b;
        }
        case "===":
            return primitiveEquals(value, cond.value, root);
        case "!==":
            // Only a present primitive can be "different"; objects/arrays are not comparable.
            return isPrimitive(value) && !primitiveEquals(value, cond.value, root);
        case "contains": {
            if (typeof value === "string" && typeof cond.value === "string")
                return value.includes(cond.value);
            if (Array.isArray(value) && isPrimitive(cond.value))
                return value.some((v) => primitiveEquals(v, cond.value, root));
            return false;
        }
        case "in": {
            if (!Array.isArray(cond.value))
                return false;
            return cond.value.some((candidate) => primitiveEquals(value, candidate, root));
        }
        case "regex": {
            if (typeof value !== "string" || typeof cond.value !== "string")
                return false;
            if (value.length > exports.MAX_REGEX_INPUT)
                return false;
            return compileRegex(cond.value, cond.flags).test(value);
        }
        default:
            return false;
    }
}
/** Evaluates a rule against a request. Never throws: any internal error is a BLOCK. */
function evaluateRule(rule, input) {
    try {
        const tiers = rule.policies ?? [];
        for (let i = 0; i < tiers.length; i++) {
            const tier = tiers[i];
            if (tier.when.length > 0 && tier.when.every((c) => evaluateCondition(c, input))) {
                return { mode: tier.mode, matched: `tier:${tier.name && tier.name.trim() ? tier.name.trim() : `#${i + 1}`}` };
            }
        }
        return { mode: rule.mode, matched: "rule" };
    }
    catch (err) {
        console.error("Policy evaluation failed, blocking the request:", err);
        return { mode: "BLOCK", matched: "error" };
    }
}
/** True when any condition in the rule reads the request body. */
function policiesReadBody(rule) {
    return (rule.policies ?? []).some((t) => t.when.some((c) => c.field.trim().startsWith("body.")));
}
function validateCondition(raw, where) {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        return { ok: false, message: `${where} must be an object like { "field": "body.amount", "op": ">", "value": 100 }.` };
    }
    const c = raw;
    if (typeof c.field !== "string")
        return { ok: false, message: `${where}.field must be a string.` };
    const parsed = parseFieldPath(c.field);
    if ("error" in parsed)
        return { ok: false, message: `${where}: ${parsed.error}` };
    if (typeof c.op !== "string" || !exports.POLICY_OPERATORS.includes(c.op)) {
        return { ok: false, message: `${where}.op must be one of ${exports.POLICY_OPERATORS.join(" ")}.` };
    }
    const op = c.op;
    const field = c.field.trim();
    const out = { field, op };
    switch (op) {
        case ">":
        case "<":
        case ">=":
        case "<=":
            if (typeof c.value !== "number" || !Number.isFinite(c.value)) {
                return { ok: false, message: `${where}.value must be a number for "${op}".` };
            }
            out.value = c.value;
            break;
        case "===":
        case "!==":
            if (!isPrimitive(c.value))
                return { ok: false, message: `${where}.value must be a string, number, boolean or null for "${op}".` };
            if (typeof c.value === "string" && c.value.length > exports.MAX_POLICY_STRING) {
                return { ok: false, message: `${where}.value is too long.` };
            }
            out.value = c.value;
            break;
        case "contains":
            if (!isPrimitive(c.value) || c.value === null) {
                return { ok: false, message: `${where}.value must be a string, number or boolean for "contains".` };
            }
            if (typeof c.value === "string" && (c.value.length === 0 || c.value.length > exports.MAX_POLICY_STRING)) {
                return { ok: false, message: `${where}.value must be 1-${exports.MAX_POLICY_STRING} characters.` };
            }
            out.value = c.value;
            break;
        case "in":
            if (!Array.isArray(c.value) || c.value.length === 0 || c.value.length > exports.MAX_IN_VALUES || !c.value.every(isPrimitive)) {
                return { ok: false, message: `${where}.value must be a list of 1-${exports.MAX_IN_VALUES} strings/numbers/booleans for "in".` };
            }
            out.value = [...c.value];
            break;
        case "regex": {
            if (typeof c.value !== "string" || c.value.length === 0 || c.value.length > exports.MAX_REGEX_LENGTH) {
                return { ok: false, message: `${where}.value must be a regular expression of 1-${exports.MAX_REGEX_LENGTH} characters.` };
            }
            if (NESTED_QUANTIFIER.test(c.value)) {
                return { ok: false, message: `${where}.value has nested quantifiers like (a+)+, which can hang the gateway. Simplify it.` };
            }
            if (c.flags !== undefined && c.flags !== "" && c.flags !== "i") {
                return { ok: false, message: `${where}.flags may only be "i".` };
            }
            try {
                new RegExp(c.value, c.flags === "i" ? "i" : "");
            }
            catch {
                return { ok: false, message: `${where}.value is not a valid regular expression.` };
            }
            out.value = c.value;
            if (c.flags === "i")
                out.flags = "i";
            break;
        }
        case "exists":
            if (c.value !== undefined && typeof c.value !== "boolean") {
                return { ok: false, message: `${where}.value must be true or false for "exists".` };
            }
            out.value = c.value === undefined ? true : c.value;
            break;
    }
    return { ok: true, condition: out };
}
/** Strict validation used by the admin API. `null`/`undefined` mean "no policies". */
function validatePolicies(raw) {
    if (raw === undefined || raw === null)
        return { ok: true, policies: [] };
    if (!Array.isArray(raw))
        return { ok: false, message: "policies must be a list of tiers." };
    if (raw.length > exports.MAX_POLICY_TIERS)
        return { ok: false, message: `A rule can have at most ${exports.MAX_POLICY_TIERS} policy tiers.` };
    const tiers = [];
    for (let i = 0; i < raw.length; i++) {
        const where = `policies[${i}]`;
        const t = raw[i];
        if (typeof t !== "object" || t === null || Array.isArray(t))
            return { ok: false, message: `${where} must be an object.` };
        if (typeof t.mode !== "string" || !constants_1.RULE_MODES.includes(t.mode)) {
            return { ok: false, message: `${where}.mode must be ALLOW, BLOCK or REQUIRE_APPROVAL.` };
        }
        if (t.name !== undefined && (typeof t.name !== "string" || t.name.length > 80)) {
            return { ok: false, message: `${where}.name must be a string of at most 80 characters.` };
        }
        if (!Array.isArray(t.when) || t.when.length === 0 || t.when.length > exports.MAX_POLICY_CONDITIONS) {
            return { ok: false, message: `${where}.when must list 1-${exports.MAX_POLICY_CONDITIONS} conditions.` };
        }
        const when = [];
        for (let j = 0; j < t.when.length; j++) {
            const r = validateCondition(t.when[j], `${where}.when[${j}]`);
            if (!r.ok)
                return r;
            when.push(r.condition);
        }
        const tier = { when, mode: t.mode };
        if (typeof t.name === "string" && t.name.trim() !== "")
            tier.name = t.name.trim();
        tiers.push(tier);
    }
    return { ok: true, policies: tiers };
}
/**
 * Used when loading rules.json. Returns the tiers, or "invalid" when the file has policies
 * that do not validate: the caller then loads the whole rule as BLOCK, because silently
 * dropping a BLOCK tier could otherwise turn a guarded endpoint into an open one.
 */
function normalizePolicies(raw) {
    if (raw === undefined || raw === null)
        return undefined;
    const result = validatePolicies(raw);
    if (!result.ok) {
        console.error(`Invalid policies in rules.json (${result.message}); the rule is enforced as BLOCK.`);
        return "invalid";
    }
    return result.policies.length > 0 ? result.policies : undefined;
}
// ---------------------------------------------------------------------------
// Budget / dedupe validation (stateful guards live in guards.ts)
// ---------------------------------------------------------------------------
const MAX_WINDOW_MINUTES = 30 * 24 * 60;
function validateBudget(raw) {
    if (raw === undefined || raw === null)
        return { ok: true, value: undefined };
    if (typeof raw !== "object" || Array.isArray(raw))
        return { ok: false, message: "budget must be an object." };
    const b = raw;
    if (typeof b.field !== "string" || "error" in parseFieldPath(b.field) || !b.field.trim().startsWith("body.")) {
        return { ok: false, message: 'budget.field must be a body field such as "body.amount".' };
    }
    if (typeof b.max !== "number" || !Number.isFinite(b.max) || b.max < 0)
        return { ok: false, message: "budget.max must be a number of at least 0." };
    if (!Number.isInteger(b.windowMinutes) || b.windowMinutes < 1 || b.windowMinutes > MAX_WINDOW_MINUTES) {
        return { ok: false, message: `budget.windowMinutes must be a whole number from 1 to ${MAX_WINDOW_MINUTES}.` };
    }
    const per = b.per ?? "global";
    if (per !== "global" && per !== "caller")
        return { ok: false, message: 'budget.per must be "global" or "caller".' };
    const onExceed = b.onExceed ?? "REQUIRE_APPROVAL";
    if (onExceed !== "REQUIRE_APPROVAL" && onExceed !== "BLOCK")
        return { ok: false, message: 'budget.onExceed must be "REQUIRE_APPROVAL" or "BLOCK".' };
    return { ok: true, value: { field: b.field.trim(), max: b.max, windowMinutes: b.windowMinutes, per, onExceed } };
}
function validateDedupe(raw) {
    if (raw === undefined || raw === null)
        return { ok: true, value: undefined };
    if (typeof raw !== "object" || Array.isArray(raw))
        return { ok: false, message: "dedupe must be an object." };
    const d = raw;
    if (!Array.isArray(d.fields) || d.fields.length === 0 || d.fields.length > 5)
        return { ok: false, message: "dedupe.fields must list 1-5 fields." };
    for (const f of d.fields) {
        if (typeof f !== "string" || "error" in parseFieldPath(f) || !f.trim().startsWith("body.")) {
            return { ok: false, message: 'dedupe.fields must be body fields such as "body.orderId".' };
        }
    }
    if (!Number.isInteger(d.windowMinutes) || d.windowMinutes < 1 || d.windowMinutes > MAX_WINDOW_MINUTES) {
        return { ok: false, message: `dedupe.windowMinutes must be a whole number from 1 to ${MAX_WINDOW_MINUTES}.` };
    }
    const onDuplicate = d.onDuplicate ?? "BLOCK";
    if (onDuplicate !== "BLOCK" && onDuplicate !== "REQUIRE_APPROVAL")
        return { ok: false, message: 'dedupe.onDuplicate must be "BLOCK" or "REQUIRE_APPROVAL".' };
    return { ok: true, value: { fields: d.fields.map((f) => f.trim()), windowMinutes: d.windowMinutes, onDuplicate } };
}
