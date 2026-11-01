import net from "net";
import {
  LOGIN_MAX_FAILURES,
  LOGIN_WINDOW_MS,
  MAX_TRACKED_IPS,
  RATE_WINDOW_MS,
} from "./constants";

/**
 * The key used to count a client. IPv4 is used as is. IPv6 is reduced to its
 * /64 prefix, because one subscriber normally owns a whole /64 and can rotate
 * through billions of addresses inside it to dodge a per-address limit.
 */
export function bucketIp(ip: string): string {
  let a = ip.trim().toLowerCase();
  const zone = a.indexOf("%");
  if (zone >= 0) a = a.slice(0, zone);
  if (a.startsWith("::ffff:") && net.isIPv4(a.slice(7))) return a.slice(7);
  if (net.isIPv4(a)) return a;
  if (!net.isIPv6(a) || a.includes(".")) return a;

  let groups: string[];
  if (a.includes("::")) {
    const [head, tail] = a.split("::");
    const left = head ? head.split(":") : [];
    const right = tail ? tail.split(":") : [];
    groups = [...left, ...Array<string>(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
  } else {
    groups = a.split(":");
  }
  return `${groups
    .slice(0, 4)
    .map((g) => g.padStart(4, "0"))
    .join(":")}::/64`;
}

interface Bucket {
  count: number;
  windowStart: number;
}

export interface Limiters {
  /** `firstLimited` is true only on the first rejected request of a window (log once, not per request). */
  checkRateLimit(ip: string, limit: number, scope?: string): { limited: boolean; firstLimited: boolean; retryAfterSec: number };
  /** `max` defaults to LOGIN_MAX_FAILURES. */
  checkLoginLockout(key: string, max?: number): { locked: boolean; retryAfterSec: number };
  recordLoginFailure(key: string): void;
  clearLoginFailures(key: string): void;
  /** Drops expired entries. Call on a timer. */
  sweep(now?: number): void;
}

// Maps never grow past MAX_TRACKED_IPS: if an attacker sprays addresses, the
// oldest entry is evicted instead of exhausting memory.
function setBounded(map: Map<string, Bucket>, key: string, value: Bucket): void {
  if (!map.has(key) && map.size >= MAX_TRACKED_IPS) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, value);
}

export function createLimiters(): Limiters {
  const rateBuckets = new Map<string, Bucket>();
  const loginFailures = new Map<string, Bucket>();

  return {
    checkRateLimit(ip, limit, scope) {
      // Per-rule limits get their own bucket: "<ip>:<rule key>".
      const key = scope ? `${bucketIp(ip)}:${scope}` : bucketIp(ip);
      const now = Date.now();
      const bucket = rateBuckets.get(key);

      if (!bucket || now - bucket.windowStart >= RATE_WINDOW_MS) {
        setBounded(rateBuckets, key, { count: 1, windowStart: now });
        return { limited: false, firstLimited: false, retryAfterSec: 0 };
      }

      bucket.count += 1;
      if (bucket.count > limit) {
        const retryAfterSec = Math.max(1, Math.ceil((bucket.windowStart + RATE_WINDOW_MS - now) / 1000));
        return { limited: true, firstLimited: bucket.count === limit + 1, retryAfterSec };
      }
      return { limited: false, firstLimited: false, retryAfterSec: 0 };
    },

    checkLoginLockout(key, max = LOGIN_MAX_FAILURES) {
      const now = Date.now();
      const entry = loginFailures.get(key);
      if (!entry || now - entry.windowStart >= LOGIN_WINDOW_MS) {
        return { locked: false, retryAfterSec: 0 };
      }
      if (entry.count >= max) {
        const retryAfterSec = Math.max(1, Math.ceil((entry.windowStart + LOGIN_WINDOW_MS - now) / 1000));
        return { locked: true, retryAfterSec };
      }
      return { locked: false, retryAfterSec: 0 };
    },

    recordLoginFailure(key) {
      const now = Date.now();
      const entry = loginFailures.get(key);
      if (!entry || now - entry.windowStart >= LOGIN_WINDOW_MS) {
        setBounded(loginFailures, key, { count: 1, windowStart: now });
      } else {
        entry.count += 1;
      }
    },

    clearLoginFailures(key) {
      loginFailures.delete(key);
    },

    sweep(now = Date.now()) {
      for (const [k, bucket] of rateBuckets) {
        if (now - bucket.windowStart >= RATE_WINDOW_MS) rateBuckets.delete(k);
      }
      for (const [k, entry] of loginFailures) {
        if (now - entry.windowStart >= LOGIN_WINDOW_MS) loginFailures.delete(k);
      }
    },
  };
}
