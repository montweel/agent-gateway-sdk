import type { PolicyTier, Rule, Rules } from "./types";
import { normalizeRule, parseRuleKey, ruleKey, validateRulePath } from "./utils";
import { validateBudget, validateDedupe, validatePolicies } from "./policy";

/**
 * 1-click starter policy packs. Keys use "*" wildcards (see rules.ts), so a pack works on
 * /api/refund, /api/v2/orders/123/refund, /api/shop/refunds, ... without editing.
 * Anything a pack does not mention stays default-deny.
 */

export interface PolicyPreset {
  id: string;
  name: string;
  summary: string;
  /** Plain-language bullet points for the Setup tab. */
  highlights: string[];
  rules: Rules;
}

const approveAbove = (field: string, limit: number, name: string): PolicyTier => ({
  name,
  when: [{ field, op: ">", value: limit }],
  mode: "REQUIRE_APPROVAL",
});
const allowUpTo = (field: string, limit: number, name: string): PolicyTier => ({
  name,
  when: [{ field, op: "<=", value: limit }],
  mode: "ALLOW",
});

// Refunds / discounts: approval when amount > 50 OR percentage > 20. The two "approve" tiers come
// first so a request that trips either one is held even if the other field looks small. A request
// with neither field falls back to REQUIRE_APPROVAL (fail-closed).
const MONEY_OUT_TIERS: PolicyTier[] = [
  approveAbove("body.amount", 50, "amount over $50"),
  approveAbove("body.percentage", 20, "discount over 20%"),
  allowUpTo("body.amount", 50, "small amount"),
  allowUpTo("body.percentage", 20, "small discount"),
];

// Bulk writes: an array body, an "ids" list, or more than one item.
const BULK_TIERS: PolicyTier[] = [
  { name: "array body (bulk)", when: [{ field: "body.0", op: "exists", value: true }], mode: "REQUIRE_APPROVAL" },
  { name: "ids list (bulk)", when: [{ field: "body.ids", op: "exists", value: true }], mode: "REQUIRE_APPROVAL" },
  { name: "multiple items (bulk)", when: [{ field: "body.items.1", op: "exists", value: true }], mode: "REQUIRE_APPROVAL" },
];

export const POLICY_PRESETS: PolicyPreset[] = [
  {
    id: "ecommerce",
    name: "E-Commerce & Shopify Store Protection",
    summary: "Reads go through, money-out actions over $50 / 20% need you, deleting customers or products is impossible.",
    highlights: [
      "GET on any orders / products route: allowed",
      "POST refund or discount: auto-allowed up to $50 and 20%, approval above that (10/min cap)",
      "Refunds: at most $300 auto-refunded per hour in total; beyond that you approve",
      "The same order can never be refunded twice within 24 hours",
      "DELETE customers or products: always blocked",
    ],
    rules: {
      "GET /api/*orders*": { mode: "ALLOW", description: "Order reads" },
      "GET /api/*products*": { mode: "ALLOW", description: "Product reads" },
      "POST /api/*refund*": {
        mode: "REQUIRE_APPROVAL",
        description: "Refunds: approval above $50, $300/hour auto-refund budget, one refund per order",
        rateLimit: 10,
        policies: MONEY_OUT_TIERS,
        budget: { field: "body.amount", max: 300, windowMinutes: 60, per: "global", onExceed: "REQUIRE_APPROVAL" },
        dedupe: { fields: ["body.orderId"], windowMinutes: 24 * 60, onDuplicate: "BLOCK" },
      },
      "POST /api/*discount*": {
        mode: "REQUIRE_APPROVAL",
        description: "Discounts: approval above $50 or 20%",
        rateLimit: 10,
        policies: MONEY_OUT_TIERS,
      },
      "DELETE /api/*customers*": { mode: "BLOCK", description: "Agents may never delete customers" },
      "DELETE /api/*products*": { mode: "BLOCK", description: "Agents may never delete products" },
    },
  },
  {
    id: "fintech",
    name: "Stripe & FinTech Protection",
    summary: "Transfers and payouts over $100 need you, charge creation is capped at 5/min, account deletion is blocked.",
    highlights: [
      "POST transfer / payout: auto-allowed up to $100, approval above (amounts in major units; use 10000 if your API sends cents)",
      "Transfers + payouts: at most $1,000 auto-approved per day each; beyond that you approve",
      "Same amount to the same destination twice within 10 minutes: held for you (duplicate payment)",
      "POST charge: allowed, max 5 per minute per caller",
      "DELETE account: always blocked",
    ],
    rules: {
      "POST /api/*transfer*": {
        mode: "REQUIRE_APPROVAL",
        description: "Transfers: approval above $100, $1,000/day auto budget, duplicate-payment check",
        policies: [allowUpTo("body.amount", 100, "transfer up to $100")],
        budget: { field: "body.amount", max: 1000, windowMinutes: 24 * 60, per: "global", onExceed: "REQUIRE_APPROVAL" },
        dedupe: { fields: ["body.destination", "body.amount"], windowMinutes: 10, onDuplicate: "REQUIRE_APPROVAL" },
      },
      "POST /api/*payout*": {
        mode: "REQUIRE_APPROVAL",
        description: "Payouts: approval above $100, $1,000/day auto budget, duplicate-payment check",
        policies: [allowUpTo("body.amount", 100, "payout up to $100")],
        budget: { field: "body.amount", max: 1000, windowMinutes: 24 * 60, per: "global", onExceed: "REQUIRE_APPROVAL" },
        dedupe: { fields: ["body.destination", "body.amount"], windowMinutes: 10, onDuplicate: "REQUIRE_APPROVAL" },
      },
      "POST /api/*charge*": { mode: "ALLOW", description: "Charge creation, rate-limited", rateLimit: 5 },
      "DELETE /api/*account*": { mode: "BLOCK", description: "Agents may never delete accounts" },
    },
  },
  {
    id: "crud",
    name: "Internal CRUD & Database API",
    summary: "Reads allowed, writes rate-limited, bulk updates need you, every DELETE is blocked.",
    highlights: [
      "GET anything under /api: allowed",
      "POST / PUT / PATCH: allowed at 30 per minute; bulk payloads (arrays, ids lists, many items) need approval",
      "Routes containing \"bulk\": always need approval",
      "DELETE anything: always blocked",
    ],
    rules: {
      "GET /api/*": { mode: "ALLOW", description: "Reads" },
      "POST /api/*": { mode: "ALLOW", description: "Creates (rate-limited, bulk needs approval)", rateLimit: 30, policies: BULK_TIERS },
      "PUT /api/*": { mode: "ALLOW", description: "Updates (rate-limited, bulk needs approval)", rateLimit: 30, policies: BULK_TIERS },
      "PATCH /api/*": { mode: "ALLOW", description: "Updates (rate-limited, bulk needs approval)", rateLimit: 30, policies: BULK_TIERS },
      "POST /api/*bulk*": { mode: "REQUIRE_APPROVAL", description: "Bulk endpoints", rateLimit: 10 },
      "PUT /api/*bulk*": { mode: "REQUIRE_APPROVAL", description: "Bulk endpoints", rateLimit: 10 },
      "PATCH /api/*bulk*": { mode: "REQUIRE_APPROVAL", description: "Bulk endpoints", rateLimit: 10 },
      "DELETE /api/*": { mode: "BLOCK", description: "Deletes are never allowed for agents" },
    },
  },
];

export function findPreset(id: string): PolicyPreset | undefined {
  return POLICY_PRESETS.find((p) => p.id === id);
}

/**
 * Merges (or replaces with) a pack. Every rule is re-validated with the same code that loads
 * rules.json, so a pack can never install something the admin API would refuse.
 */
export function applyPreset(current: Rules, preset: PolicyPreset, mode: "merge" | "replace"): { rules: Rules; added: string[]; replaced: string[] } {
  const next: Rules = mode === "replace" ? {} : { ...current };
  const added: string[] = [];
  const replaced: string[] = [];
  for (const [rawKey, rawRule] of Object.entries(preset.rules)) {
    const parsed = parseRuleKey(rawKey);
    if ("error" in parsed) throw new Error(`Preset ${preset.id} has an invalid key ${rawKey}: ${parsed.error}`);
    const problem = validateRulePath(parsed.path);
    if (problem) throw new Error(`Preset ${preset.id} has an invalid path ${rawKey}: ${problem}`);
    if (rawRule.policies) {
      const v = validatePolicies(rawRule.policies);
      if (!v.ok) throw new Error(`Preset ${preset.id} rule ${rawKey}: ${v.message}`);
    }
    const b = validateBudget(rawRule.budget);
    const d = validateDedupe(rawRule.dedupe);
    if (!b.ok || !d.ok) throw new Error(`Preset ${preset.id} rule ${rawKey}: invalid budget/dedupe.`);
    const rule = normalizeRule(rawRule) as Rule;
    const key = ruleKey(parsed.method, parsed.path);
    if (mode === "merge" && Object.prototype.hasOwnProperty.call(current, key)) replaced.push(key);
    else added.push(key);
    next[key] = structuredClone(rule);
  }
  return { rules: next, added, replaced };
}
