"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compilePathPattern = compilePathPattern;
exports.isPatternKey = isPatternKey;
exports.lookupInRules = lookupInRules;
exports.parseRulesObject = parseRulesObject;
exports.createRulesStore = createRulesStore;
exports.matcherFor = matcherFor;
const fileCache_1 = require("./fileCache");
const utils_1 = require("./utils");
/** "*" matches any run of characters (including "/") within the path; everything else is literal. */
function compilePathPattern(path) {
    const body = path
        .split("*")
        .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
        .join("[^?#]*");
    return new RegExp(`^${body}$`);
}
function isPatternKey(key) {
    return key.includes("*");
}
function compilePatterns(rules) {
    const out = [];
    for (const key of Object.keys(rules)) {
        if (!isPatternKey(key))
            continue;
        const parsed = (0, utils_1.parseRuleKey)(key);
        if ("error" in parsed)
            continue;
        out.push({ key, method: parsed.method, re: compilePathPattern(parsed.path), score: parsed.path.replace(/\*/g, "").length });
    }
    // Method-specific first, then most specific, then key order (deterministic).
    out.sort((a, b) => {
        if ((a.method === null) !== (b.method === null))
            return a.method === null ? 1 : -1;
        if (a.score !== b.score)
            return b.score - a.score;
        return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    });
    return out;
}
/** Pure lookup over a rules object (exported for presets / tests). */
function lookupInRules(rules, patterns, method, endpoint) {
    const m = method.toUpperCase();
    // MCP tool calls are governed only by explicit "MCP ..." rules, never by any-method HTTP rules.
    const exactKeys = m === "MCP" ? [`${m} ${endpoint}`] : [`${m} ${endpoint}`, endpoint];
    for (const key of exactKeys) {
        if (Object.prototype.hasOwnProperty.call(rules, key) && !isPatternKey(key))
            return { key, rule: rules[key] };
    }
    for (const p of patterns) {
        if (p.method === null && m === "MCP")
            continue;
        if (p.method !== null && p.method !== m)
            continue;
        if (p.re.test(endpoint))
            return { key: p.key, rule: rules[p.key] };
    }
    return undefined;
}
/**
 * Normalises a parsed rules object (rules.json, or a workspace's rules in SQLite). Invalid keys
 * are dropped (= default deny); rules whose policies / guards cannot be trusted load as BLOCK.
 */
function parseRulesObject(raw) {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw))
        return {};
    const rules = {};
    for (const [rawKey, value] of Object.entries(raw)) {
        const parsed = (0, utils_1.parseRuleKey)(rawKey);
        if ("error" in parsed)
            continue;
        // Only valid gateway paths are accepted. This also rejects "__proto__",
        // traversal ("..") and whitespace/control characters in hand-edited files.
        if ((0, utils_1.validateRulePath)(parsed.path) !== null)
            continue;
        const rule = (0, utils_1.normalizeRule)(value);
        if (rule)
            rules[(0, utils_1.ruleKey)(parsed.method, parsed.path)] = rule;
    }
    return rules;
}
function createRulesStore(rulesPath) {
    const cache = (0, fileCache_1.createFileCache)(rulesPath, (text) => {
        if (text === null)
            return {};
        try {
            return parseRulesObject(JSON.parse(text));
        }
        catch (err) {
            console.error("Could not read rules.json, treating all paths as blocked:", err);
            return {};
        }
    });
    // Patterns are compiled once per rules.json version (the cache hands back the same object until it changes).
    let compiledFor = null;
    let patterns = [];
    function current() {
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
            (0, utils_1.writeJsonAtomic)(rulesPath, rules);
            cache.invalidate();
        },
    };
}
/** Compiles patterns for an arbitrary rules object (presets preview / tests). */
function matcherFor(rules) {
    const patterns = compilePatterns(rules);
    return (method, endpoint) => lookupInRules(rules, patterns, method, endpoint);
}
