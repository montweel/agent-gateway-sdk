import type { BudgetSpec, DedupeSpec, PolicyCondition, PolicyOperator, PolicyTier, Rule, RuleMode } from "./types";
import { RULE_MODES } from "./constants";

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

export const POLICY_OPERATORS: PolicyOperator[] = [">", "<", ">=", "<=", "===", "!==", "contains", "in", "regex", "exists"];
export const POLICY_ROOTS = ["body", "query", "headers"] as const;
export type PolicyRoot = (typeof POLICY_ROOTS)[number];

export const MAX_POLICY_TIERS = 20;
export const MAX_POLICY_CONDITIONS = 10;
export const MAX_POLICY_FIELD_LENGTH = 200;
export const MAX_POLICY_PATH_DEPTH = 12;
export const MAX_REGEX_LENGTH = 256;
export const MAX_REGEX_INPUT = 4096;
export const MAX_IN_VALUES = 100;
export const MAX_POLICY_STRING = 1000;

const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);
const NUMERIC_STRING = /^-?(?:0|[1-9]\d{0,15})(?:\.\d{1,15})?$/;
// Nested quantifiers such as (a+)+ or (a*)* are the classic catastrophic-backtracking shapes.
const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]/;

export interface PolicyInput {
  body: unknown;
  query: unknown;
  /** Lower-cased header names. */
  headers: Record<string, string | string[] | undefined>;
}

export interface PolicyDecision {
  mode: RuleMode;
  /** "tier:<name or #n>" when a tier matched, "rule" when the base mode applied, "error" when evaluation failed. */
  matched: string;
}

type Primitive = string | number | boolean | null;

function isPrimitive(v: unknown): v is Primitive {
  return v === null || typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

function own(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** Splits "body.items.0.price" into ["body", "items", "0", "price"], or returns an error. */
export function parseFieldPath(field: string): { root: PolicyRoot; segments: string[] } | { error: string } {
  if (typeof field !== "string" || field.trim() === "") return { error: "field must be a non-empty string." };
  if (field.length > MAX_POLICY_FIELD_LENGTH) return { error: `field must be ${MAX_POLICY_FIELD_LENGTH} characters or fewer.` };
  const parts = field.trim().split(".");
  const root = parts[0] as PolicyRoot;
  if (!POLICY_ROOTS.includes(root)) return { error: 'field must start with "body.", "query." or "headers."' };
  const segments = parts.slice(1);
  if (segments.length === 0) return { error: `field "${field}" needs a key after "${root}."` };
  if (segments.length > MAX_POLICY_PATH_DEPTH) return { error: `field "${field}" is nested too deeply.` };
  for (const s of segments) {
    if (s === "") return { error: `field "${field}" has an empty segment.` };
    if (FORBIDDEN_SEGMENTS.has(s)) return { error: `field "${field}" uses a reserved key.` };
  }
  return { root, segments: root === "headers" ? segments.map((s) => s.toLowerCase()) : segments };
}

/** Resolves a field against the request. Own properties only; arrays accept numeric indexes. */
export function resolveField(input: PolicyInput, field: string): { found: boolean; value: unknown; root: PolicyRoot | null } {
  const parsed = parseFieldPath(field);
  if ("error" in parsed) return { found: false, value: undefined, root: null };

  let current: unknown;
  if (parsed.root === "headers") {
    // Header names may contain dots in theory; join the rest so "headers.x-agent-reason" works.
    const name = parsed.segments.join(".");
    const raw = input.headers[name];
    if (raw === undefined) return { found: false, value: undefined, root: "headers" };
    return { found: true, value: Array.isArray(raw) ? raw.join(", ") : raw, root: "headers" };
  }

  current = parsed.root === "body" ? input.body : input.query;
  for (const seg of parsed.segments) {
    if (Array.isArray(current)) {
      if (!/^\d{1,6}$/.test(seg)) return { found: false, value: undefined, root: parsed.root };
      const idx = Number(seg);
      if (idx >= current.length) return { found: false, value: undefined, root: parsed.root };
      current = current[idx];
    } else if (typeof current === "object" && current !== null) {
      if (!own(current, seg)) return { found: false, value: undefined, root: parsed.root };
      current = (current as Record<string, unknown>)[seg];
    } else {
      return { found: false, value: undefined, root: parsed.root };
    }
  }
  return { found: current !== undefined, value: current, root: parsed.root };
}

/** Numbers for comparison. Body: real JSON numbers only. Query/headers: canonical decimal strings. */
function asNumber(value: unknown, root: PolicyRoot | null): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if ((root === "query" || root === "headers") && typeof value === "string" && NUMERIC_STRING.test(value)) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** Equality used by === !== and in. Strict, except that a query/header string may equal a number. */
function primitiveEquals(actual: unknown, expected: unknown, root: PolicyRoot | null): boolean {
  if (!isPrimitive(actual)) return false;
  if (actual === expected) return true;
  if (typeof expected === "number" && (root === "query" || root === "headers")) {
    const n = asNumber(actual, root);
    return n !== null && n === expected;
  }
  if (typeof expected === "boolean" && (root === "query" || root === "headers") && typeof actual === "string") {
    return actual === String(expected);
  }
  return false;
}

const regexCache = new Map<string, RegExp>();

function compileRegex(pattern: string, flags: string | undefined): RegExp {
  const f = flags === "i" ? "i" : "";
  const key = `${f}/${pattern}`;
  let re = regexCache.get(key);
  if (!re) {
    re = new RegExp(pattern, f);
    if (regexCache.size > 1000) regexCache.clear();
    regexCache.set(key, re);
  }
  return re;
}

export function evaluateCondition(cond: PolicyCondition, input: PolicyInput): boolean {
  const { found, value, root } = resolveField(input, cond.field);

  if (cond.op === "exists") {
    const want = cond.value === undefined ? true : cond.value === true;
    return found === want;
  }
  if (!found) return false;

  switch (cond.op) {
    case ">":
    case "<":
    case ">=":
    case "<=": {
      const a = asNumber(value, root);
      const b = typeof cond.value === "number" && Number.isFinite(cond.value) ? cond.value : null;
      if (a === null || b === null) return false;
      if (cond.op === ">") return a > b;
      if (cond.op === "<") return a < b;
      if (cond.op === ">=") return a >= b;
      return a <= b;
    }
    case "===":
      return primitiveEquals(value, cond.value, root);
    case "!==":
      // Only a present primitive can be "different"; objects/arrays are not comparable.
      return isPrimitive(value) && !primitiveEquals(value, cond.value, root);
    case "contains": {
      if (typeof value === "string" && typeof cond.value === "string") return value.includes(cond.value);
      if (Array.isArray(value) && isPrimitive(cond.value)) return value.some((v) => primitiveEquals(v, cond.value, root));
      return false;
    }
    case "in": {
      if (!Array.isArray(cond.value)) return false;
      return cond.value.some((candidate) => primitiveEquals(value, candidate, root));
    }
    case "regex": {
      if (typeof value !== "string" || typeof cond.value !== "string") return false;
      if (value.length > MAX_REGEX_INPUT) return false;
      return compileRegex(cond.value, cond.flags).test(value);
    }
    default:
      return false;
  }
}

/** Evaluates a rule against a request. Never throws: any internal error is a BLOCK. */
export function evaluateRule(rule: Rule, input: PolicyInput): PolicyDecision {
  try {
    const tiers = rule.policies ?? [];
    for (let i = 0; i < tiers.length; i++) {
      const tier = tiers[i];
      if (tier.when.length > 0 && tier.when.every((c) => evaluateCondition(c, input))) {
        return { mode: tier.mode, matched: `tier:${tier.name && tier.name.trim() ? tier.name.trim() : `#${i + 1}`}` };
      }
    }
    return { mode: rule.mode, matched: "rule" };
  } catch (err) {
    console.error("Policy evaluation failed, blocking the request:", err);
    return { mode: "BLOCK", matched: "error" };
  }
}

export type ShadowVerdict = "BLOCK" | "APPROVAL";

/**
 * Shadow ("dry run") modes are enforced as ALLOW; the verdict they would have given is returned
 * separately so the audit row can record it and the dashboard can count "would have blocked".
 */
export function splitShadow(d: PolicyDecision): { decision: PolicyDecision; shadow: ShadowVerdict | null } {
  if (d.mode === "SHADOW_BLOCK") return { decision: { mode: "ALLOW", matched: d.matched }, shadow: "BLOCK" };
  if (d.mode === "SHADOW_APPROVAL") return { decision: { mode: "ALLOW", matched: d.matched }, shadow: "APPROVAL" };
  return { decision: d, shadow: null };
}

/** True when any condition in the rule reads the request body. */
export function policiesReadBody(rule: Rule): boolean {
  return (rule.policies ?? []).some((t) => t.when.some((c) => c.field.trim().startsWith("body.")));
}

function validateCondition(raw: unknown, where: string): { ok: true; condition: PolicyCondition } | { ok: false; message: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, message: `${where} must be an object like { "field": "body.amount", "op": ">", "value": 100 }.` };
  }
  const c = raw as { field?: unknown; op?: unknown; value?: unknown; flags?: unknown };
  if (typeof c.field !== "string") return { ok: false, message: `${where}.field must be a string.` };
  const parsed = parseFieldPath(c.field);
  if ("error" in parsed) return { ok: false, message: `${where}: ${parsed.error}` };
  if (typeof c.op !== "string" || !POLICY_OPERATORS.includes(c.op as PolicyOperator)) {
    return { ok: false, message: `${where}.op must be one of ${POLICY_OPERATORS.join(" ")}.` };
  }
  const op = c.op as PolicyOperator;
  const field = c.field.trim();
  const out: PolicyCondition = { field, op };

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
      if (!isPrimitive(c.value)) return { ok: false, message: `${where}.value must be a string, number, boolean or null for "${op}".` };
      if (typeof c.value === "string" && c.value.length > MAX_POLICY_STRING) {
        return { ok: false, message: `${where}.value is too long.` };
      }
      out.value = c.value;
      break;
    case "contains":
      if (!isPrimitive(c.value) || c.value === null) {
        return { ok: false, message: `${where}.value must be a string, number or boolean for "contains".` };
      }
      if (typeof c.value === "string" && (c.value.length === 0 || c.value.length > MAX_POLICY_STRING)) {
        return { ok: false, message: `${where}.value must be 1-${MAX_POLICY_STRING} characters.` };
      }
      out.value = c.value;
      break;
    case "in":
      if (!Array.isArray(c.value) || c.value.length === 0 || c.value.length > MAX_IN_VALUES || !c.value.every(isPrimitive)) {
        return { ok: false, message: `${where}.value must be a list of 1-${MAX_IN_VALUES} strings/numbers/booleans for "in".` };
      }
      out.value = [...c.value];
      break;
    case "regex": {
      if (typeof c.value !== "string" || c.value.length === 0 || c.value.length > MAX_REGEX_LENGTH) {
        return { ok: false, message: `${where}.value must be a regular expression of 1-${MAX_REGEX_LENGTH} characters.` };
      }
      if (NESTED_QUANTIFIER.test(c.value)) {
        return { ok: false, message: `${where}.value has nested quantifiers like (a+)+, which can hang the gateway. Simplify it.` };
      }
      if (c.flags !== undefined && c.flags !== "" && c.flags !== "i") {
        return { ok: false, message: `${where}.flags may only be "i".` };
      }
      try {
        new RegExp(c.value, c.flags === "i" ? "i" : "");
      } catch {
        return { ok: false, message: `${where}.value is not a valid regular expression.` };
      }
      out.value = c.value;
      if (c.flags === "i") out.flags = "i";
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
export function validatePolicies(raw: unknown): { ok: true; policies: PolicyTier[] } | { ok: false; message: string } {
  if (raw === undefined || raw === null) return { ok: true, policies: [] };
  if (!Array.isArray(raw)) return { ok: false, message: "policies must be a list of tiers." };
  if (raw.length > MAX_POLICY_TIERS) return { ok: false, message: `A rule can have at most ${MAX_POLICY_TIERS} policy tiers.` };

  const tiers: PolicyTier[] = [];
  for (let i = 0; i < raw.length; i++) {
    const where = `policies[${i}]`;
    const t = raw[i] as { name?: unknown; when?: unknown; mode?: unknown } | null;
    if (typeof t !== "object" || t === null || Array.isArray(t)) return { ok: false, message: `${where} must be an object.` };
    if (typeof t.mode !== "string" || !RULE_MODES.includes(t.mode as RuleMode)) {
      return { ok: false, message: `${where}.mode must be ALLOW, BLOCK or REQUIRE_APPROVAL.` };
    }
    if (t.name !== undefined && (typeof t.name !== "string" || t.name.length > 80)) {
      return { ok: false, message: `${where}.name must be a string of at most 80 characters.` };
    }
    if (!Array.isArray(t.when) || t.when.length === 0 || t.when.length > MAX_POLICY_CONDITIONS) {
      return { ok: false, message: `${where}.when must list 1-${MAX_POLICY_CONDITIONS} conditions.` };
    }
    const when: PolicyCondition[] = [];
    for (let j = 0; j < t.when.length; j++) {
      const r = validateCondition(t.when[j], `${where}.when[${j}]`);
      if (!r.ok) return r;
      when.push(r.condition);
    }
    const tier: PolicyTier = { when, mode: t.mode as RuleMode };
    if (typeof t.name === "string" && t.name.trim() !== "") tier.name = t.name.trim();
    tiers.push(tier);
  }
  return { ok: true, policies: tiers };
}

/**
 * Used when loading rules.json. Returns the tiers, or "invalid" when the file has policies
 * that do not validate: the caller then loads the whole rule as BLOCK, because silently
 * dropping a BLOCK tier could otherwise turn a guarded endpoint into an open one.
 */
export function normalizePolicies(raw: unknown): PolicyTier[] | "invalid" | undefined {
  if (raw === undefined || raw === null) return undefined;
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

type Check<T> = { ok: true; value: T } | { ok: false; message: string };

export function validateBudget(raw: unknown): Check<BudgetSpec | undefined> {
  if (raw === undefined || raw === null) return { ok: true, value: undefined };
  if (typeof raw !== "object" || Array.isArray(raw)) return { ok: false, message: "budget must be an object." };
  const b = raw as Record<string, unknown>;
  if (typeof b.field !== "string" || "error" in parseFieldPath(b.field) || !b.field.trim().startsWith("body.")) {
    return { ok: false, message: 'budget.field must be a body field such as "body.amount".' };
  }
  if (typeof b.max !== "number" || !Number.isFinite(b.max) || b.max < 0) return { ok: false, message: "budget.max must be a number of at least 0." };
  if (!Number.isInteger(b.windowMinutes) || (b.windowMinutes as number) < 1 || (b.windowMinutes as number) > MAX_WINDOW_MINUTES) {
    return { ok: false, message: `budget.windowMinutes must be a whole number from 1 to ${MAX_WINDOW_MINUTES}.` };
  }
  const per = b.per ?? "global";
  if (per !== "global" && per !== "caller") return { ok: false, message: 'budget.per must be "global" or "caller".' };
  const onExceed = b.onExceed ?? "REQUIRE_APPROVAL";
  if (onExceed !== "REQUIRE_APPROVAL" && onExceed !== "BLOCK") return { ok: false, message: 'budget.onExceed must be "REQUIRE_APPROVAL" or "BLOCK".' };
  return { ok: true, value: { field: b.field.trim(), max: b.max, windowMinutes: b.windowMinutes as number, per, onExceed } };
}

export function validateDedupe(raw: unknown): Check<DedupeSpec | undefined> {
  if (raw === undefined || raw === null) return { ok: true, value: undefined };
  if (typeof raw !== "object" || Array.isArray(raw)) return { ok: false, message: "dedupe must be an object." };
  const d = raw as Record<string, unknown>;
  if (!Array.isArray(d.fields) || d.fields.length === 0 || d.fields.length > 5) return { ok: false, message: "dedupe.fields must list 1-5 fields." };
  for (const f of d.fields) {
    if (typeof f !== "string" || "error" in parseFieldPath(f) || !f.trim().startsWith("body.")) {
      return { ok: false, message: 'dedupe.fields must be body fields such as "body.orderId".' };
    }
  }
  if (!Number.isInteger(d.windowMinutes) || (d.windowMinutes as number) < 1 || (d.windowMinutes as number) > MAX_WINDOW_MINUTES) {
    return { ok: false, message: `dedupe.windowMinutes must be a whole number from 1 to ${MAX_WINDOW_MINUTES}.` };
  }
  const onDuplicate = d.onDuplicate ?? "BLOCK";
  if (onDuplicate !== "BLOCK" && onDuplicate !== "REQUIRE_APPROVAL") return { ok: false, message: 'dedupe.onDuplicate must be "BLOCK" or "REQUIRE_APPROVAL".' };
  return { ok: true, value: { fields: (d.fields as string[]).map((f) => f.trim()), windowMinutes: d.windowMinutes as number, onDuplicate } };
}
