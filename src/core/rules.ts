import type { Rule, Rules } from "./types";
import { createFileCache } from "./fileCache";
import { normalizeRule, parseRuleKey, ruleKey, validateRulePath, writeJsonAtomic } from "./utils";

export interface RulesStore {
  /** Cached; re-read only when rules.json changes on disk. Returns a shallow copy. */
  load(): Rules;
  /**
   * Hot-path lookup, no copying. Precedence:
   *   1. "<METHOD> <path>"   2. "<path>" (any method)   3. undefined (caller blocks)
   */
  lookup(method: string, endpoint: string): Rule | undefined;
  /** Like lookup, but also returns the rules.json key that matched (used to scope per-rule rate limits). */
  lookupEntry(method: string, endpoint: string): { key: string; rule: Rule } | undefined;
  save(rules: Rules): void;
}

export function createRulesStore(rulesPath: string): RulesStore {
  const cache = createFileCache<Rules>(rulesPath, (text) => {
    if (text === null) return {};
    try {
      const raw = JSON.parse(text) as unknown;
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};

      const rules: Rules = {};
      for (const [rawKey, value] of Object.entries(raw as Record<string, unknown>)) {
        const parsed = parseRuleKey(rawKey);
        if ("error" in parsed) continue;
        // Only valid gateway paths are accepted. This also rejects "__proto__",
        // traversal ("..") and whitespace/control characters in hand-edited files.
        if (validateRulePath(parsed.path) !== null) continue;
        const rule = normalizeRule(value);
        if (rule) rules[ruleKey(parsed.method, parsed.path)] = rule;
      }
      return rules;
    } catch (err) {
      console.error("Could not read rules.json, treating all paths as blocked:", err);
      return {};
    }
  });

  const own = (rules: Rules, key: string): Rule | undefined =>
    Object.prototype.hasOwnProperty.call(rules, key) ? rules[key] : undefined;

  return {
    load: () => ({ ...cache.get() }),
    lookup(method, endpoint) {
      const rules = cache.get();
      return own(rules, `${method.toUpperCase()} ${endpoint}`) ?? own(rules, endpoint);
    },
    lookupEntry(method, endpoint) {
      const rules = cache.get();
      for (const key of [`${method.toUpperCase()} ${endpoint}`, endpoint]) {
        const rule = own(rules, key);
        if (rule) return { key, rule };
      }
      return undefined;
    },
    save(rules) {
      writeJsonAtomic(rulesPath, rules);
      cache.invalidate();
    },
  };
}
