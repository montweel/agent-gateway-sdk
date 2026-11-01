"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createUserCountCache = createUserCountCache;
function createUserCountCache(db) {
    let cached;
    let generation = 0; // guards against an in-flight read caching a stale value after invalidate()
    return {
        async get() {
            if (cached !== undefined)
                return cached;
            const gen = generation;
            const row = await db.get("SELECT COUNT(*) as count FROM users");
            const count = row?.count ?? 0;
            if (gen === generation)
                cached = count;
            return count;
        },
        invalidate() {
            generation += 1;
            cached = undefined;
        },
    };
}
