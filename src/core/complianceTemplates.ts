import type { Rule, Rules } from "./types";
import { applyPreset } from "./presets";
import { parseRuleKey } from "./utils";

/**
 * Industry compliance templates: a redaction profile (audit.redactKeys), the frameworks an install
 * reports against, and recommended REQUIRE_APPROVAL route rules.
 *
 * Applying a template only ever ADDS:
 *   - its redact keys are merged into audit.redactKeys (existing keys are kept);
 *   - its rules (when asked for) are added only where they do not override a decision already made:
 *     a rule with the same key, or an explicit BLOCK / REQUIRE_APPROVAL rule that already covers the
 *     route, wins. Routes that are only default-denied get the template rule, which is the point:
 *     the route becomes usable, with a human approving each call.
 */

export type ComplianceTemplateId = "fintech" | "retail" | "travel" | "custom";

export const COMPLIANCE_TEMPLATE_IDS: ComplianceTemplateId[] = ["fintech", "retail", "travel", "custom"];

/** Framework tags offered in the dashboard. Any other short tag is accepted too. */
export const KNOWN_FRAMEWORKS = ["SOC2", "PCI-DSS", "GDPR", "CCPA", "HIPAA", "ISO 27001"];

export interface ComplianceTemplate {
  id: ComplianceTemplateId;
  name: string;
  summary: string;
  frameworks: string[];
  redactKeys: string[];
  rules: Rules;
}

const approval = (description: string): Rule => ({ mode: "REQUIRE_APPROVAL", description });

export const COMPLIANCE_TEMPLATES: ComplianceTemplate[] = [
  {
    id: "fintech",
    name: "Fintech & Banking",
    summary: "PCI-DSS / SOC2: card and bank identifiers redacted; transfers, payouts, refunds and deletes need a human.",
    frameworks: ["PCI-DSS", "SOC2"],
    redactKeys: ["cvv", "cvc", "pan", "iban", "swift", "routing_number", "account_number", "ifsc", "pin", "tax_id", "ssn"],
    rules: {
      "POST /api/*transfer*": approval("Fintech template: fund transfers need human approval (PCI-DSS / SOC2)"),
      "POST /api/*payout*": approval("Fintech template: payouts need human approval (PCI-DSS / SOC2)"),
      "POST /api/*refund*": approval("Fintech template: refunds need human approval (PCI-DSS / SOC2)"),
      "DELETE /api/*": approval("Fintech template: deletes need human approval (SOC2 change control)"),
    },
  },
  {
    id: "retail",
    name: "Retail & E-Commerce",
    summary: "GDPR / CCPA: shopper PII and payment data redacted; refunds, price changes, discounts and customer deletes need a human.",
    frameworks: ["GDPR", "CCPA"],
    redactKeys: ["card_number", "cvv", "billing_address", "shipping_address", "phone_number", "loyalty_token", "gift_card_code", "dob"],
    rules: {
      "POST /api/*refund*": approval("Retail template: refunds need human approval"),
      "PUT /api/*price*": approval("Retail template: price changes need human approval"),
      "PATCH /api/*price*": approval("Retail template: price changes need human approval"),
      "POST /api/*discount*": approval("Retail template: discounts need human approval"),
      "DELETE /api/*customer*": approval("Retail template: customer deletion needs human approval (GDPR / CCPA erasure)"),
    },
  },
  {
    id: "travel",
    name: "Travel & Hospitality",
    summary: "PNR / passenger PII redacted; cancellations, booking changes and ticket issuance need a human.",
    frameworks: ["GDPR", "PCI-DSS"],
    redactKeys: ["passport_number", "pnr", "ticket_number", "visa_number", "national_id", "dob", "frequent_flyer_id", "emergency_contact"],
    rules: {
      "POST /api/*cancel*": approval("Travel template: cancellations need human approval"),
      "PUT /api/*booking*": approval("Travel template: booking changes need human approval"),
      "PATCH /api/*booking*": approval("Travel template: booking changes need human approval"),
      "DELETE /api/*booking*": approval("Travel template: booking deletion needs human approval"),
      "POST /api/*ticket*": approval("Travel template: ticket issuance needs human approval"),
    },
  },
  {
    id: "custom",
    name: "Custom Compliance Profile",
    summary: "Your own framework tags and redact keys; no route rules.",
    frameworks: [],
    redactKeys: [],
    rules: {},
  },
];

export function findComplianceTemplate(id: string): ComplianceTemplate | undefined {
  return COMPLIANCE_TEMPLATES.find((t) => t.id === id);
}

/** Framework tags: trimmed, 1-32 characters, de-duplicated (case-insensitively), at most 20. */
export function cleanFrameworks(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const v of value) {
    if (typeof v !== "string") return null;
    const t = v.trim();
    if (!t || t.length > 32 || !/^[\w .\-/]+$/.test(t)) return null;
    if (!out.some((x) => x.toLowerCase() === t.toLowerCase())) out.push(t);
  }
  return out.slice(0, 20);
}

/** Existing keys first (in their order), then the template's new ones. Compared case-insensitively. */
export function mergeRedactKeys(existing: string[], add: string[]): { keys: string[]; added: string[] } {
  const keys = [...existing];
  const added: string[] = [];
  for (const k of add) {
    if (!keys.some((x) => x.toLowerCase() === k.toLowerCase())) {
      keys.push(k);
      added.push(k);
    }
  }
  return { keys, added };
}

/** A concrete path the pattern matches, used to ask "what decides this route today?". */
function samplePath(pattern: string): string {
  const p = pattern.replace(/\*/g, "");
  return p.endsWith("/") ? `${p}x` : p;
}

export interface TemplateRulesResult {
  rules: Rules;
  added: string[];
  skipped: Array<{ key: string; reason: string }>;
}

/**
 * Adds the template's rules where they do not override an existing decision (see the header).
 * `lookup` answers which current rule decides a method + path (undefined = default deny).
 */
export function mergeTemplateRules(
  current: Rules,
  template: ComplianceTemplate,
  lookup: (method: string, path: string) => { key: string; rule: Rule } | undefined
): TemplateRulesResult {
  // Same validation as policy packs, so a template can never install a rule the admin API would refuse.
  const validated = applyPreset({}, { id: `template:${template.id}`, name: template.name, summary: "", highlights: [], rules: template.rules }, "merge").rules;
  const next: Rules = { ...current };
  const added: string[] = [];
  const skipped: Array<{ key: string; reason: string }> = [];
  for (const [key, rule] of Object.entries(validated)) {
    if (Object.prototype.hasOwnProperty.call(current, key)) {
      skipped.push({ key, reason: "a rule with this key already exists (kept as is)" });
      continue;
    }
    const parsed = parseRuleKey(key);
    if (!("error" in parsed) && parsed.method) {
      const decided = lookup(parsed.method, samplePath(parsed.path));
      if (decided && (decided.rule.mode === "BLOCK" || decided.rule.mode === "REQUIRE_APPROVAL")) {
        skipped.push({
          key,
          reason: decided.rule.mode === "BLOCK" ? `"${decided.key}" already blocks it (kept stricter)` : `"${decided.key}" already holds it for approval`,
        });
        continue;
      }
    }
    next[key] = rule;
    added.push(key);
  }
  return { rules: next, added, skipped };
}
