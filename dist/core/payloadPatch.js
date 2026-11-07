"use strict";
/**
 * "Edit & Approve": merges what the approver edited into the ORIGINAL request.
 *
 * The approver only ever sees the redacted copy (emails masked, secrets "[REDACTED]"). Forwarding
 * their edited copy verbatim would replace the real values with the masks. So the edit is applied
 * as a diff against what they were shown:
 *
 *   - a value the approver did not change keeps its ORIGINAL (unredacted) value
 *   - a value they changed (or added) takes their new value
 *   - a key they removed is removed
 *
 * Arrays are compared index by index; extra elements the approver appended are taken as typed.
 * Deterministic, pure, no prototype pollution (only own enumerable keys, "__proto__" refused).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PatchError = void 0;
exports.deepEqual = deepEqual;
exports.assertJsonValue = assertJsonValue;
exports.applyEdits = applyEdits;
exports.describeChanges = describeChanges;
exports.validateQueryEdit = validateQueryEdit;
exports.withQuery = withQuery;
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);
class PatchError extends Error {
    constructor(message) {
        super(message);
        this.name = "PatchError";
    }
}
exports.PatchError = PatchError;
function isPlainObject(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
function deepEqual(a, b) {
    if (a === b)
        return true;
    if (Array.isArray(a) && Array.isArray(b))
        return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
    if (isPlainObject(a) && isPlainObject(b)) {
        const ka = Object.keys(a);
        const kb = Object.keys(b);
        return ka.length === kb.length && ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]));
    }
    return false;
}
/** Rejects values JSON cannot carry faithfully (and prototype-polluting keys). */
function assertJsonValue(v, depth = 0) {
    if (depth > 32)
        throw new PatchError("The edited payload is nested too deeply.");
    if (v === null || typeof v === "string" || typeof v === "boolean")
        return;
    if (typeof v === "number") {
        if (!Number.isFinite(v))
            throw new PatchError("Numbers in the edited payload must be finite.");
        return;
    }
    if (Array.isArray(v)) {
        for (const x of v)
            assertJsonValue(x, depth + 1);
        return;
    }
    if (isPlainObject(v)) {
        for (const [k, x] of Object.entries(v)) {
            if (FORBIDDEN_KEYS.has(k))
                throw new PatchError(`The key "${k}" is not allowed.`);
            assertJsonValue(x, depth + 1);
        }
        return;
    }
    throw new PatchError("The edited payload must be plain JSON.");
}
/**
 * @param original the real request value (decrypted)
 * @param shown    the redacted value the approver saw
 * @param edited   what the approver submitted
 */
function applyEdits(original, shown, edited, depth = 0) {
    if (depth > 32)
        throw new PatchError("The edited payload is nested too deeply.");
    if (deepEqual(shown, edited))
        return original;
    if (isPlainObject(shown) && isPlainObject(edited) && isPlainObject(original)) {
        const out = {};
        for (const [k, v] of Object.entries(edited)) {
            if (FORBIDDEN_KEYS.has(k))
                throw new PatchError(`The key "${k}" is not allowed.`);
            out[k] = Object.prototype.hasOwnProperty.call(shown, k) && Object.prototype.hasOwnProperty.call(original, k) ? applyEdits(original[k], shown[k], v, depth + 1) : v;
        }
        return out;
    }
    if (Array.isArray(shown) && Array.isArray(edited) && Array.isArray(original)) {
        return edited.map((v, i) => (i < shown.length && i < original.length ? applyEdits(original[i], shown[i], v, depth + 1) : v));
    }
    return edited;
}
/** Flat list of "path: before -> after" lines for the audit detail (values are already redacted by the caller). */
function describeChanges(shown, edited, prefix = "body", out = [], depth = 0) {
    if (out.length >= 20 || depth > 12)
        return out;
    if (deepEqual(shown, edited))
        return out;
    if (isPlainObject(shown) && isPlainObject(edited)) {
        for (const k of new Set([...Object.keys(shown), ...Object.keys(edited)])) {
            if (!Object.prototype.hasOwnProperty.call(edited, k))
                out.push(`${prefix}.${k} removed`);
            else if (!Object.prototype.hasOwnProperty.call(shown, k))
                out.push(`${prefix}.${k} added = ${JSON.stringify(edited[k]).slice(0, 80)}`);
            else
                describeChanges(shown[k], edited[k], `${prefix}.${k}`, out, depth + 1);
        }
        return out;
    }
    out.push(`${prefix}: ${JSON.stringify(shown)?.slice(0, 80)} -> ${JSON.stringify(edited)?.slice(0, 80)}`);
    return out;
}
/** Validates an edited query object: string values or lists of strings. */
function validateQueryEdit(v) {
    if (!isPlainObject(v))
        throw new PatchError("modifiedQuery must be an object of query parameters.");
    const out = {};
    for (const [k, x] of Object.entries(v)) {
        if (FORBIDDEN_KEYS.has(k) || k.length > 200)
            throw new PatchError(`The query parameter "${k.slice(0, 40)}" is not allowed.`);
        if (typeof x === "string")
            out[k] = x;
        else if (typeof x === "number" || typeof x === "boolean")
            out[k] = String(x);
        else if (Array.isArray(x) && x.every((y) => typeof y === "string"))
            out[k] = x;
        else
            throw new PatchError(`Query parameter "${k}" must be a string or a list of strings.`);
    }
    return out;
}
/** "/api/refund?x=1" + { x: "2", y: ["a","b"] } -> "/api/refund?x=2&y=a&y=b" */
function withQuery(path, query) {
    const base = path.split("?")[0];
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
        if (Array.isArray(v))
            for (const x of v)
                params.append(k, x);
        else
            params.append(k, v);
    }
    const qs = params.toString();
    return qs ? `${base}?${qs}` : base;
}
