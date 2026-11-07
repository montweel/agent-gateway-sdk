import type { Rule, Rules } from "./types";
import { createFileCache } from "./fileCache";
import { normalizeRule, parseRuleKey, ruleKey, validateRulePath, writeJsonAtomic } from "./utils";

export interface RulesStore {
  /** Cached; re-read only when rules.json changes on disk. Returns a shallow copy. */
  load(): Rules;
  /**
   * Hot-path lookup, no copying. Precedence (first hit wins):
   *   1. exact "<METHOD> <path>"
   *   2. exact "<path>" (any method)
   *   3. wildcard "<METHOD> <pattern>"  e.g. "DELETE /api/*customers*"
   *   4. wildcard "<pattern>"           e.g. "/api/*"
   *   5. undefined (caller blocks: default deny)
   * Among wildcards of the same tier, the most specific (most literal characters) wins,
   * ties broken by key order, so the result never depends on file order.
   */
  lookup(method: string, endpoint: string): Rule | undefined;
  /** Like lookup, but also returns the rules.json key that matched (used to scope per-rule rate limits). */
  lookupEntry(method: string, endpoint: string): { key: string; rule: Rule } | undefined;
  save(rules: Rules): void;
}

interface Pattern {
  key: string;
  method: string | null;
  re: RegExp;
  /** Literal (non-*) characters: higher = more specific. */
  score: number;
}

/** "*" matches any run of characters (including "/") within the path; everything else is literal. */
export function compilePathPattern(path: string): RegExp {
  const body = path
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join("[^?#]*");
  return new RegExp(`^${body}$`);
}

export function isPatternKey(key: string): boolean {
  return key.includes("*");
}

function compilePatterns(rules: Rules): Pattern[] {
  const out: Pattern[] = [];
  for (const key of Object.keys(rules)) {
    if (!isPatternKey(key)) continue;
    const parsed = parseRuleKey(key);
    if ("error" in parsed) continue;
    out.push({ key, method: parsed.method, re: compilePathPattern(parsed.path), score: parsed.path.replace(/\*/g, "").length });
  }
  // Method-specific first, then most specific, then key order (deterministic).
  out.sort((a, b) => {
    if ((a.method === null) !== (b.method === null)) return a.method === null ? 1 : -1;
    if (a.score !== b.score) return b.score - a.score;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
  return out;
}

/** Pure lookup over a rules object (exported for presets / tests). */
export function lookupInRules(rules: Rules, patterns: Pattern[], method: string, endpoint: string): { key: string; rule: Rule } | undefined {
  const m = method.toUpperCase();
  // MCP tool calls are governed only by explicit "MCP ..." rules, never by any-method HTTP rules.
  const exactKeys = m === "MCP" ? [`${m} ${endpoint}`] : [`${m} ${endpoint}`, endpoint];
  for (const key of exactKeys) {
    if (Object.prototype.hasOwnProperty.call(rules, key) && !isPatternKey(key)) return { key, rule: rules[key] };
  }
  for (const p of patterns) {
    if (p.method === null && m === "MCP") continue;
    if (p.method !== null && p.method !== m) continue;
    if (p.re.test(endpoint)) return { key: p.key, rule: rules[p.key] };
  }
  return undefined;
}

/**
 * Normalises a parsed rules object (rules.json, or a workspace's rules in SQLite). Invalid keys
 * are dropped (= default deny); rules whose policies / guards cannot be trusted load as BLOCK.
 */
export function parseRulesObject(raw: unknown): Rules {
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
}

export function createRulesStore(rulesPath: string): RulesStore {
  const cache = createFileCache<Rules>(rulesPath, (text) => {
    if (text === null) return {};
    try {
      return parseRulesObject(JSON.parse(text) as unknown);
    } catch (err) {
      console.error("Could not read rules.json, treating all paths as blocked:", err);
      return {};
    }
  });

  // Patterns are compiled once per rules.json version (the cache hands back the same object until it changes).
  let compiledFor: Rules | null = null;
  let patterns: Pattern[] = [];
  function current(): { rules: Rules; patterns: Pattern[] } {
    const rules = cache.get();
    if (rules !== compiledFor) {
      patterns = compilePatterns(rules);
      compiledFor = rules;
    }
    return { rules, patterns };
  }

  return {
    load: () => ({ ...cache.get() }),
    lookup(method, endpoint) {
      const { rules, patterns: p } = current();
      return lookupInRules(rules, p, method, endpoint)?.rule;
    },
    lookupEntry(method, endpoint) {
      const { rules, patterns: p } = current();
      return lookupInRules(rules, p, method, endpoint);
    },
    save(rules) {
      writeJsonAtomic(rulesPath, rules);
      cache.invalidate();
    },
  };
}

/** Compiles patterns for an arbitrary rules object (presets preview / tests). */
export function matcherFor(rules: Rules): (method: string, endpoint: string) => { key: string; rule: Rule } | undefined {
  const patterns = compilePatterns(rules);
  return (method, endpoint) => lookupInRules(rules, patterns, method, endpoint);
}
