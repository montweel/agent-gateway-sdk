"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRulesStore = createRulesStore;
const fileCache_1 = require("./fileCache");
const utils_1 = require("./utils");
function createRulesStore(rulesPath) {
    const cache = (0, fileCache_1.createFileCache)(rulesPath, (text) => {
        if (text === null)
            return {};
        try {
            const raw = JSON.parse(text);
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
        catch (err) {
            console.error("Could not read rules.json, treating all paths as blocked:", err);
            return {};
        }
    });
    const own = (rules, key) => Object.prototype.hasOwnProperty.call(rules, key) ? rules[key] : undefined;
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
                if (rule)
                    return { key, rule };
            }
            return undefined;
        },
        save(rules) {
            (0, utils_1.writeJsonAtomic)(rulesPath, rules);
            cache.invalidate();
        },
    };
}
