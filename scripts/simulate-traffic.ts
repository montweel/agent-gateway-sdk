/**
 * Load test: fire a mix of agent requests at a running Mont gateway and report what came back.
 *
 * Every request goes to one of ENDPOINTS below: POST /api/refund (payload tiers + budget), an
 * explicitly blocked route, and several routes that have no rule of their own. Routes with no
 * matching rule are refused by default deny and show up in Audit Logs as UNKNOWN ENDPOINT, with a
 * "Create Rule" button. (A catch-all rule such as "/api/*" matches them, so they are then allowed
 * and are not unknown.)
 *
 *   npx tsx scripts/simulate-traffic.ts
 *
 * Environment (all optional):
 *   MONT_URL          gateway base URL. Default http://127.0.0.1:3000, which is `npm run dev` / `npm start`
 *                     (src/server.ts, middleware mode: gateway and mock API on one port). The standalone
 *                     proxy (`npm run proxy`, src/cli.ts) listens on 8080 instead.
 *                     Use 127.0.0.1, not localhost: the server binds IPv4 only and Node may resolve
 *                     localhost to ::1, which fails with ECONNREFUSED.
 *   MONT_TOTAL        number of requests (default 4000)
 *   MONT_CONCURRENCY  requests in flight at once (default 50)
 *   MONT_AGENT_KEY    agent key (agk_...) or workspace key (mws_...), sent as x-agent-key. Only needed
 *                     when "Require agent API key" is on; a key also names the agent in the audit log.
 *   MONT_WORKSPACE    workspace slug, sent as x-mont-workspace (default: the default workspace)
 *   MONT_ONLY_REFUND  "1" to send only POST /api/refund (the original scenario)
 *
 * What to expect: rate limits are per caller IP. A rule with its own rateLimit has its own bucket
 * (POST /api/refund: 15/min in the shipped rules.json); every route without one shares the global
 * bucket (rateLimitPerMinute, 60 by default). From one machine only that many requests per bucket get
 * past the limiter each minute; the rest get 429. The gateway writes ONE RATE_LIMITED audit row per
 * caller per bucket per window, not one per rejected request.
 */

interface Endpoint {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  /** Relative share of the traffic. */
  weight: number;
  body?: (index: number) => Record<string, unknown>;
}

const randomAmount = (): number => 1 + Math.floor(Math.random() * 120);

const ENDPOINTS: Endpoint[] = [
  // Has a rule: payload tiers (< 50 allow, > 50 approval) and a spending budget.
  { method: "POST", path: "/api/refund", weight: 4, body: (i) => ({ order_id: `SHOP-${1000 + i}`, amount: randomAmount(), currency: "USD", reason: "customer request" }) },
  // Has a rule: explicitly blocked. Shows as BLOCKED, not as an unknown endpoint.
  { method: "DELETE", path: "/api/delete_account", weight: 1, body: (i) => ({ customer_id: `CUST-${i % 40}` }) },
  // No rule of their own: new tools an agent is trying to use.
  { method: "POST", path: "/api/apply-discount", weight: 2, body: (i) => ({ order_id: `SHOP-${1000 + i}`, percent: 5 + (i % 4) * 5, code: "LOADTEST" }) },
  { method: "GET", path: "/api/order-status", weight: 2 },
  { method: "POST", path: "/api/cancel-order", weight: 1, body: (i) => ({ order_id: `SHOP-${1000 + i}`, reason: "changed mind" }) },
  { method: "PATCH", path: "/api/update-shipping-address", weight: 1, body: (i) => ({ order_id: `SHOP-${1000 + i}`, city: "Pune", postcode: "411001" }) },
  { method: "GET", path: "/api/inventory", weight: 1 },
  { method: "POST", path: "/api/issue-store-credit", weight: 1, body: (i) => ({ customer_id: `CUST-${i % 40}`, amount: randomAmount() }) },
];

const ACTIVE_ENDPOINTS = process.env.MONT_ONLY_REFUND === "1" ? ENDPOINTS.slice(0, 1) : ENDPOINTS;
const TOTAL_WEIGHT = ACTIVE_ENDPOINTS.reduce((s, e) => s + e.weight, 0);

function pickEndpoint(): Endpoint {
  let r = Math.random() * TOTAL_WEIGHT;
  for (const e of ACTIVE_ENDPOINTS) {
    r -= e.weight;
    if (r < 0) return e;
  }
  return ACTIVE_ENDPOINTS[0];
}

const BASE_URL = (process.env.MONT_URL ?? "http://127.0.0.1:3000").replace(/\/+$/, "");
const TOTAL = positiveInt(process.env.MONT_TOTAL, 4000);
const CONCURRENCY = positiveInt(process.env.MONT_CONCURRENCY, 50);
const AGENT_KEY = process.env.MONT_AGENT_KEY ?? "";
const WORKSPACE = process.env.MONT_WORKSPACE ?? "";
const TIMEOUT_MS = 15_000;

function positiveInt(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

type Outcome = ({ kind: "http"; status: number; body: string; retryAfter: string | null } | { kind: "error"; code: string; message: string }) & { route: string };

/** Network errors from fetch hide the real reason (ECONNREFUSED, ...) in err.cause. */
function describeError(err: unknown): { code: string; message: string } {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  if (e?.name === "TimeoutError" || e?.name === "AbortError") return { code: "TIMEOUT", message: `no response within ${TIMEOUT_MS} ms` };
  const code = e?.cause?.code ?? e?.name ?? "ERROR";
  return { code, message: e?.cause?.message ?? e?.message ?? String(err) };
}

function headers(index: number, hasBody: boolean): Record<string, string> {
  const h: Record<string, string> = {
    "user-agent": "mont-load-test/1.0",
    // Shown to the approver on queued requests (and in the Telegram / Slack message).
    "x-mont-justification": `Load test request #${index}`,
  };
  // Required with a body: routes with payload policies refuse non-JSON bodies (415).
  if (hasBody) h["content-type"] = "application/json";
  if (AGENT_KEY) h["x-agent-key"] = AGENT_KEY;
  if (WORKSPACE) h["x-mont-workspace"] = WORKSPACE;
  return h;
}

async function fireRequest(index: number): Promise<Outcome> {
  const ep = pickEndpoint();
  const route = `${ep.method} ${ep.path}`;
  // Refund amounts 1..120 cover every tier in the shipped rule: < 50 ALLOW, > 50 approval, 50 the fallback.
  const payload = ep.body?.(index);
  try {
    const res = await fetch(`${BASE_URL}${ep.path}`, {
      method: ep.method,
      headers: headers(index, payload !== undefined),
      body: payload !== undefined ? JSON.stringify(payload) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const body = await res.text();
    return { route, kind: "http", status: res.status, body, retryAfter: res.headers.get("retry-after") };
  } catch (err) {
    return { route, kind: "error", ...describeError(err) };
  }
}

/** Fails fast with a clear message when nothing is listening, instead of 4,000 silent errors. */
async function preflight(): Promise<void> {
  try {
    const res = await fetch(`${BASE_URL}/.well-known/agent.json`, { signal: AbortSignal.timeout(5000) });
    await res.arrayBuffer();
    console.log(`Gateway reachable at ${BASE_URL} (GET /.well-known/agent.json -> ${res.status})`);
  } catch (err) {
    const { code, message } = describeError(err);
    console.error(`Cannot reach the gateway at ${BASE_URL}: ${code} (${message}).`);
    console.error("Start it with `npm run dev` (port 3000) or `npm run proxy` (port 8080), or set MONT_URL.");
    process.exit(1);
  }
}

const STATUS_MEANING: Record<number, string> = {
  200: "allowed and forwarded",
  202: "queued for human approval",
  401: "agent key missing / invalid",
  403: "blocked by a rule, a policy, or default deny (no rule)",
  404: "allowed by the gateway, but the app behind it has no such route",
  415: "body was not JSON",
  429: "rate limited",
  503: "no upstream / gateway unavailable",
};

function truncate(s: string, n = 160): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? `${one.slice(0, n)}...` : one;
}

async function run(): Promise<void> {
  console.log(`Mont load test: ${TOTAL} requests to ${BASE_URL} across ${ACTIVE_ENDPOINTS.length} endpoint(s), ${CONCURRENCY} in flight`);
  if (AGENT_KEY) console.log("Using agent key from MONT_AGENT_KEY");
  if (WORKSPACE) console.log(`Workspace: ${WORKSPACE}`);
  await preflight();

  const statusCounts = new Map<number, number>();
  const errorCounts = new Map<string, number>();
  const firstSample = new Map<string, string>(); // first body / error message per outcome
  const byRoute = new Map<string, Map<string, number>>(); // route -> status code (or error code) -> count
  let next = 0;
  let done = 0;
  const started = Date.now();

  const record = (o: Outcome): void => {
    const perRoute = byRoute.get(o.route) ?? new Map<string, number>();
    const outcomeKey = o.kind === "http" ? String(o.status) : o.code;
    perRoute.set(outcomeKey, (perRoute.get(outcomeKey) ?? 0) + 1);
    byRoute.set(o.route, perRoute);
    if (o.kind === "http") {
      statusCounts.set(o.status, (statusCounts.get(o.status) ?? 0) + 1);
      const key = `HTTP ${o.status}`;
      if (!firstSample.has(key)) firstSample.set(key, truncate(o.body) + (o.retryAfter ? ` [Retry-After: ${o.retryAfter}s]` : ""));
    } else {
      errorCounts.set(o.code, (errorCounts.get(o.code) ?? 0) + 1);
      if (!firstSample.has(o.code)) firstSample.set(o.code, o.message);
    }
  };

  const progress = (): void => {
    const parts = [...statusCounts.entries()].sort(([a], [b]) => a - b).map(([s, n]) => `${s}:${n}`);
    const errs = [...errorCounts.values()].reduce((a, b) => a + b, 0);
    if (errs) parts.push(`errors:${errs}`);
    process.stdout.write(`\rSent ${done}/${TOTAL}  ${parts.join("  ")}   `);
  };

  // A fixed pool of workers keeps exactly CONCURRENCY requests in flight.
  async function worker(): Promise<void> {
    while (next < TOTAL) {
      const index = next++;
      record(await fireRequest(index));
      done++;
      if (done % 50 === 0 || done === TOTAL) progress();
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, TOTAL) }, () => worker()));

  const secs = (Date.now() - started) / 1000;
  console.log(`\n\nFinished ${TOTAL} requests in ${secs.toFixed(1)} s (${Math.round(TOTAL / secs)} req/s)\n`);
  console.log("Status codes:");
  for (const [status, n] of [...statusCounts.entries()].sort(([a], [b]) => a - b)) {
    console.log(`  ${status}  ${String(n).padStart(5)}  ${STATUS_MEANING[status] ?? ""}`);
    console.log(`        e.g. ${firstSample.get(`HTTP ${status}`)}`);
  }
  console.log("\nBy endpoint:");
  const width = Math.max(...[...byRoute.keys()].map((r) => r.length));
  for (const ep of ACTIVE_ENDPOINTS) {
    const route = `${ep.method} ${ep.path}`;
    const counts = byRoute.get(route);
    if (!counts) continue;
    const parts = [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, n]) => `${k}: ${n}`);
    console.log(`  ${route.padEnd(width)}  ${parts.join("  ")}`);
  }
  if (errorCounts.size > 0) {
    console.log("Network errors:");
    for (const [code, n] of errorCounts) console.log(`  ${code}  ${n}  e.g. ${firstSample.get(code)}`);
  }

  const httpTotal = [...statusCounts.values()].reduce((a, b) => a + b, 0);
  if (httpTotal === 0) {
    console.error("\nNo request got an HTTP response: nothing reached the gateway.");
    process.exitCode = 1;
    return;
  }
  console.log("\nCheck the dashboard: Audit Logs (tick \"Only unknown endpoints\" for the 403s that matched no rule,");
  console.log("each with a Create Rule button; one RATE_LIMITED row per caller per bucket per minute, not per 429),");
  console.log("and Approvals for the 202s. The daily digest summarises this traffic on its next run.");
}

run().catch((err: unknown) => {
  console.error("Load test crashed:", err);
  process.exitCode = 1;
});
