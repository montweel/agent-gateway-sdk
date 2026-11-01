import type { Db } from "./db";

export interface UserCountCache {
  /** Number of users. Cached in memory; call invalidate() after creating or deleting users. */
  get(): Promise<number>;
  invalidate(): void;
}

export function createUserCountCache(db: Db): UserCountCache {
  let cached: number | undefined;
  let generation = 0; // guards against an in-flight read caching a stale value after invalidate()

  return {
    async get() {
      if (cached !== undefined) return cached;
      const gen = generation;
      const row = await db.get<{ count: number }>("SELECT COUNT(*) as count FROM users");
      const count = row?.count ?? 0;
      if (gen === generation) cached = count;
      return count;
    },
    invalidate() {
      generation += 1;
      cached = undefined;
    },
  };
}
