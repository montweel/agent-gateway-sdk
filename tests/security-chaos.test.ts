/**
 * Fail-closed & chaos security suite for agent-gateway-sdk.
 *
 * Run: npm test   (node --import tsx --test tests/security-chaos.test.ts)
 *
 * Every scenario runs a real gateway (real SQLite file, real HTTP sockets) in a temp folder.
 * "Leaked" means a request reached the protected handler / upstream when it should not have.
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import http from "http";
import type { AddressInfo } from "net";
import os from "os";
import path from "path";
import express from "express";
import type { Request, Response } from "express";
import sqlite3 from "sqlite3";
import { createAgentGateway } from "../src/gateway";
import type { AgentGateway, Rules } from "../src/gateway";
import { evaluateRule, validatePolicies } from "../src/core/policy";
import { buildApprovalLink, signApprovalLink, verifyApprovalLink } from "../src/core/approvalSigning";

const ADMIN_TOKEN = "chaos-suite-admin-token-0123456789abcdef";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
interface Harness {
  base: string;
  port: number;
  dir: string;
  dbPath: string;
  gateway: AgentGateway;
  hits: Map<string, number>;
  close(): Promise<void>;
}

const cleanups: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  });
}

async function makeHarness(opts: { rules: Rules; targetUrl?: string; rateLimitPerMinute?: number; dbTimeoutMs?: number }): Promise<Harness> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mont-chaos-"));
  const rulesPath = path.join(dir, "rules.json");
  const configPath = path.join(dir, "config.json");
  const dbPath = path.join(dir, "logs.db");
  fs.writeFileSync(rulesPath, JSON.stringify(opts.rules, null, 2));
  fs.writeFileSync(
    configPath,
    JSON.stringify({ targetUrl: opts.targetUrl ?? "", rateLimitPerMinute: opts.rateLimitPerMinute ?? 1000, requireAgentApiKey: false })
  );

  const app = express();
  const server = http.createServer(app);
  const port = await listen(server);
  const gateway = createAgentGateway({
    port,
    rulesPath,
    configPath,
    dbPath,
    adminToken: ADMIN_TOKEN,
    dbOperationTimeoutMs: opts.dbTimeoutMs ?? 2000,
  });
  await gateway.ready;

  const hits = new Map<string, number>();
  const count = (req: Request, res: Response): void => {
    const key = `${req.method} ${req.path}`;
    hits.set(key, (hits.get(key) ?? 0) + 1);
    res.json({ ok: true, executed: key, body: req.body ?? null });
  };

  app.use("/api/agent-admin", gateway.adminRouter);
  app.use(gateway.approvalCallbackRouter);
  app.use("/api", gateway.agentGateway);
  // Protected business endpoints. Reaching any of these counts as "forwarded".
  app.all(/^\/api\/.*/, count);

  let closed = false;
  const h: Harness = {
    base: `http://127.0.0.1:${port}`,
    port,
    dir,
    dbPath,
    gateway,
    hits,
    async close() {
      if (closed) return;
      closed = true;
      await closeServer(server);
      await gateway.close().catch(() => undefined);
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
  cleanups.push(() => h.close());
  return h;
}

const totalHits = (h: Harness): number => [...h.hits.values()].reduce((a, b) => a + b, 0);

function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<globalThis.Response> {
  return fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
}

function sqliteGet<T>(dbPath: string, sql: string, params: unknown[] = []): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
      if (err) return reject(err);
      db.get(sql, params, (e: Error | null, row: unknown) => {
        db.close(() => (e ? reject(e) : resolve(row as T | undefined)));
      });
    });
  });
}

const REFUND_RULES: Rules = {
  "POST /api/refund": {
    mode: "REQUIRE_APPROVAL",
    description: "tiered refunds",
    policies: [
      { name: "small", when: [{ field: "body.order.refund.amount", op: "<=", value: 100 }], mode: "ALLOW" },
      { name: "huge", when: [{ field: "body.order.refund.amount", op: ">", value: 1000 }], mode: "BLOCK" },
      { name: "sanctioned-currency", when: [{ field: "body.order.currency", op: "in", value: ["XXX", "KPW"] }], mode: "BLOCK" },
    ],
  },
  "POST /api/transfer": { mode: "ALLOW", description: "" },
  "DELETE /api/customers": { mode: "BLOCK", description: "" },
};

// ---------------------------------------------------------------------------
// 1. Fail-closed under failure injection
// ---------------------------------------------------------------------------
describe("1. fail-closed under failure injection", () => {
  test("upstream that dies mid-response -> 502, never a partial 2xx", async () => {
    const upstream = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json", "content-length": "1000" });
        res.write('{"refund":"iss');
        setTimeout(() => res.socket?.destroy(), 20);
      });
    });
    const upPort = await listen(upstream);
    cleanups.push(() => closeServer(upstream));

    const h = await makeHarness({ rules: REFUND_RULES, targetUrl: `http://127.0.0.1:${upPort}` });
    const res = await postJson(`${h.base}/api/transfer`, { amount: 10 });
    const text = await res.text();
    assert.equal(res.status, 502);
    assert.ok(!text.includes("iss"), "partial upstream bytes must not reach the agent");
  });

  test("upstream that resets the connection before answering -> 502", async () => {
    const upstream = http.createServer((req) => req.socket.destroy());
    const upPort = await listen(upstream);
    cleanups.push(() => closeServer(upstream));

    const h = await makeHarness({ rules: REFUND_RULES, targetUrl: `http://127.0.0.1:${upPort}` });
    const res = await postJson(`${h.base}/api/transfer`, { amount: 10 });
    assert.equal(res.status, 502);
  });

  test("client disconnect aborts the in-flight upstream call", async () => {
    let upstreamSawAbort = false;
    let markAborted: () => void = () => undefined;
    const aborted = new Promise<void>((r) => (markAborted = r));
    const upstream = http.createServer((req, res) => {
      req.resume();
      res.on("close", () => {
        if (!res.writableFinished) {
          upstreamSawAbort = true;
          markAborted();
        }
      });
      setTimeout(() => {
        if (!res.destroyed) res.end("{}");
      }, 3000);
    });
    const upPort = await listen(upstream);
    cleanups.push(() => closeServer(upstream));

    const h = await makeHarness({ rules: REFUND_RULES, targetUrl: `http://127.0.0.1:${upPort}` });
    const ac = new AbortController();
    const req = fetch(`${h.base}/api/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      signal: ac.signal,
    }).catch(() => "aborted");
    setTimeout(() => ac.abort(), 200);
    assert.equal(await req, "aborted");
    await Promise.race([aborted, new Promise((r) => setTimeout(r, 2500))]);
    assert.equal(upstreamSawAbort, true, "the upstream request should be cancelled when the agent disconnects");
  });

  test("SQLite failure (database closed underneath the gateway) -> 503, zero requests forwarded", async () => {
    const h = await makeHarness({ rules: REFUND_RULES });
    // Sanity: forwarded while healthy.
    assert.equal((await postJson(`${h.base}/api/transfer`, { amount: 1 })).status, 200);
    assert.equal(totalHits(h), 1);

    await h.gateway.close(); // every following db.run() rejects with SQLITE_MISUSE
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => postJson(`${h.base}/api/transfer`, { amount: i })).map((p) => p.then((r) => r.status))
    );
    assert.deepEqual([...new Set(results)], [503]);
    assert.equal(totalHits(h), 1, "no request may be forwarded once the audit DB fails");

    // Queued (REQUIRE_APPROVAL) path fails closed too.
    const queued = await postJson(`${h.base}/api/refund`, { order: { refund: { amount: 500 } } });
    assert.equal(queued.status, 503);
    assert.equal(totalHits(h), 1);
  });

  test("SQLite lock held by another process past the timeout -> 503, zero forwarded, audit row corrected", async () => {
    const h = await makeHarness({ rules: REFUND_RULES, dbTimeoutMs: 300 });
    const locker = new sqlite3.Database(h.dbPath);
    const exec = (sql: string): Promise<void> => new Promise((res, rej) => locker.exec(sql, (e) => (e ? rej(e) : res())));
    await exec("PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE;");
    try {
      const started = Date.now();
      const res = await postJson(`${h.base}/api/transfer`, { amount: 5 });
      assert.equal(res.status, 503);
      assert.ok(Date.now() - started < 2500, "must fail fast, not hang on the lock");
      assert.equal(totalHits(h), 0);
    } finally {
      await exec("ROLLBACK;");
      await new Promise<void>((r) => locker.close(() => r()));
    }
    // The late-landing audit row (if any) must not say ALLOWED.
    await new Promise((r) => setTimeout(r, 300));
    const allowed = await sqliteGet<{ n: number }>(h.dbPath, "SELECT COUNT(*) AS n FROM agent_logs WHERE status = 'ALLOWED'");
    assert.equal(allowed?.n ?? 0, 0);
  });

  test("malformed JSON -> 400, never forwarded", async () => {
    const h = await makeHarness({ rules: REFUND_RULES });
    const res = await fetch(`${h.base}/api/transfer`, { method: "POST", headers: { "content-type": "application/json" }, body: '{"amount": 5,' });
    assert.equal(res.status, 400);
    assert.equal(totalHits(h), 0);
  });

  test("non-JSON body on a payload-policy route -> 415 (policy cannot be bypassed with text/plain)", async () => {
    const h = await makeHarness({ rules: REFUND_RULES });
    const res = await fetch(`${h.base}/api/refund`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: JSON.stringify({ order: { refund: { amount: 99999 } } }),
    });
    assert.equal(res.status, 415);
    assert.equal(totalHits(h), 0);
  });

  test("invalid policies in rules.json load as BLOCK (fail closed)", async () => {
    const h = await makeHarness({
      rules: {
        "POST /api/refund": {
          mode: "ALLOW",
          description: "",
          policies: [{ when: [{ field: "body.__proto__.x", op: ">", value: 1 }], mode: "BLOCK" }],
        } as unknown as Rules[string],
      },
    });
    const res = await postJson(`${h.base}/api/refund`, { amount: 1 });
    assert.equal(res.status, 403);
    assert.equal(totalHits(h), 0);
  });
});

// ---------------------------------------------------------------------------
// 2. Payload policies on nested JSON
// ---------------------------------------------------------------------------
describe("2. payload policies on nested JSON bodies", () => {
  test("engine: tiers, strict types, operators", () => {
    const rule = REFUND_RULES["POST /api/refund"];
    const at = (body: unknown) => evaluateRule(rule, { body, query: {}, headers: {} });
    assert.deepEqual(at({ order: { refund: { amount: 100 } } }), { mode: "ALLOW", matched: "tier:small" });
    assert.deepEqual(at({ order: { refund: { amount: 100.01 } } }), { mode: "REQUIRE_APPROVAL", matched: "rule" });
    assert.deepEqual(at({ order: { refund: { amount: 1000.5 } } }), { mode: "BLOCK", matched: "tier:huge" });
    assert.equal(at({ order: { refund: { amount: "50" } } }).mode, "REQUIRE_APPROVAL", "strings are never coerced in bodies");
    assert.equal(at({ order: { refund: {} } }).mode, "REQUIRE_APPROVAL", "missing field falls to the fail-closed fallback");
    assert.equal(at({ order: { refund: { amount: 5 }, currency: "KPW" } }).mode, "ALLOW", "first matching tier wins");
    assert.equal(at({ order: { refund: { amount: 500 }, currency: "KPW" } }).mode, "BLOCK");
    assert.equal(at([1, 2, 3]).mode, "REQUIRE_APPROVAL");

    const misc = validatePolicies([
      { when: [{ field: "query.limit", op: ">", value: 50 }], mode: "BLOCK" },
      { when: [{ field: "headers.x-agent-reason", op: "regex", value: "^refund", flags: "i" }], mode: "ALLOW" },
      { when: [{ field: "body.tags", op: "contains", value: "vip" }], mode: "ALLOW" },
      { when: [{ field: "body.email", op: "exists", value: true }, { field: "body.email", op: "!==", value: "owner@shop.test" }], mode: "BLOCK" },
    ]);
    assert.ok(misc.ok);
    const r = { mode: "REQUIRE_APPROVAL" as const, description: "", policies: misc.ok ? misc.policies : [] };
    assert.equal(evaluateRule(r, { body: {}, query: { limit: "51" }, headers: {} }).mode, "BLOCK", "canonical numeric query strings compare as numbers");
    assert.equal(evaluateRule(r, { body: {}, query: { limit: "5e9" }, headers: {} }).mode, "REQUIRE_APPROVAL");
    assert.equal(evaluateRule(r, { body: {}, query: {}, headers: { "x-agent-reason": "Refund for order 7" } }).mode, "ALLOW");
    assert.equal(evaluateRule(r, { body: { tags: ["new", "vip"] }, query: {}, headers: {} }).mode, "ALLOW");
    assert.equal(evaluateRule(r, { body: { email: "attacker@evil.test" }, query: {}, headers: {} }).mode, "BLOCK");
    assert.equal(evaluateRule(r, { body: { email: "owner@shop.test" }, query: {}, headers: {} }).mode, "REQUIRE_APPROVAL");

    assert.equal(validatePolicies([{ when: [{ field: "body.x", op: "regex", value: "(a+)+$" }], mode: "ALLOW" }]).ok, false, "ReDoS shapes are refused");
    assert.equal(validatePolicies([{ when: [{ field: "body.constructor", op: "exists" }], mode: "ALLOW" }]).ok, false);
    assert.equal(validatePolicies([{ when: [{ field: "amount", op: ">", value: 1 }], mode: "ALLOW" }]).ok, false);
  });

  test("HTTP: allow / queue / block by nested amount, then approve, revoke and kill-switch", async () => {
    const h = await makeHarness({ rules: REFUND_RULES });
    const agentHeaders = { "user-agent": "rogue-support-bot/1.0", "x-agent-reason": "Customer asked for a refund" };

    const small = await postJson(`${h.base}/api/refund`, { order: { refund: { amount: 50 } } }, agentHeaders);
    assert.equal(small.status, 200);
    assert.equal(h.hits.get("POST /api/refund"), 1);

    const medium = await postJson(`${h.base}/api/refund?orderId=1001`, { order: { refund: { amount: 250, email: "c@x.test" } } }, agentHeaders);
    assert.equal(medium.status, 202);
    const { approvalId } = (await medium.json()) as { approvalId: number };
    assert.equal(h.hits.get("POST /api/refund"), 1, "queued request must not execute");

    const huge = await postJson(`${h.base}/api/refund`, { order: { refund: { amount: 5000 } } }, agentHeaders);
    assert.equal(huge.status, 403);

    const stringy = await postJson(`${h.base}/api/refund`, { order: { refund: { amount: "50" } } }, agentHeaders);
    assert.equal(stringy.status, 202, '"50" as a string must not satisfy amount <= 100');

    // The approver sees payload, query, caller and the agent's reason.
    const list = (await (await fetch(`${h.base}/api/agent-admin/approvals`, { headers: { "x-admin-token": ADMIN_TOKEN } })).json()) as Array<Record<string, unknown>>;
    const row = list.find((r) => r.id === approvalId);
    assert.ok(row);
    assert.equal(JSON.parse(row.body as string).order.refund.amount, 250);
    assert.deepEqual(JSON.parse(row.query_json as string), { orderId: "1001" });
    assert.equal(row.caller_ua, "rogue-support-bot/1.0");
    assert.equal(row.agent_reason, "Customer asked for a refund");
    assert.equal(row.matched_policy, "rule");
    assert.ok(typeof row.caller_ip === "string" && (row.caller_ip as string).length > 0);
    assert.equal(row.encrypted_payload, undefined, "encrypted payload must never leave the server");

    // Approve -> replayed exactly once.
    const decide = await postJson(`${h.base}/api/agent-admin/approvals/${approvalId}/decide`, { decision: "APPROVE" }, { "x-admin-token": ADMIN_TOKEN });
    assert.equal(decide.status, 200);
    assert.equal(h.hits.get("POST /api/refund"), 2);

    // Revoke & block the caller: the stringy request still waiting is auto-rejected, and the caller is cut off.
    const revoke = await postJson(
      `${h.base}/api/agent-admin/approvals/${approvalId}/revoke`,
      { blockIp: true, blockAgentKey: true, fireRollback: false, reason: "prompt injection" },
      { "x-admin-token": ADMIN_TOKEN }
    );
    assert.equal(revoke.status, 200);
    const revoked = (await revoke.json()) as { autoRejected: number[]; blocked: unknown[] };
    assert.equal(revoked.autoRejected.length, 1);
    assert.equal(revoked.blocked.length, 1);

    const afterBlock = await postJson(`${h.base}/api/refund`, { order: { refund: { amount: 1 } } }, agentHeaders);
    assert.equal(afterBlock.status, 403, "a blocked caller is refused even for amounts that would be allowed");
    assert.equal(h.hits.get("POST /api/refund"), 2);

    const again = await postJson(`${h.base}/api/agent-admin/approvals/${approvalId}/revoke`, {}, { "x-admin-token": ADMIN_TOKEN });
    assert.equal(again.status, 409, "an action can be revoked only once");
  });
});

// ---------------------------------------------------------------------------
// 3. Runaway agent burst
// ---------------------------------------------------------------------------
describe("3. runaway agent loop", () => {
  test("50 concurrent requests against a 10/min rule -> exactly 10 forwarded, 40 x 429", async () => {
    const h = await makeHarness({
      rules: { "POST /api/agent-loop": { mode: "ALLOW", description: "", rateLimit: 10 } },
    });
    const statuses = await Promise.all(
      Array.from({ length: 50 }, (_, i) => postJson(`${h.base}/api/agent-loop`, { i }).then(async (r) => {
        await r.arrayBuffer();
        return r.status;
      }))
    );
    const ok = statuses.filter((s) => s === 200).length;
    const limited = statuses.filter((s) => s === 429).length;
    assert.equal(ok, 10);
    assert.equal(limited, 40);
    assert.equal(h.hits.get("POST /api/agent-loop"), 10);

    await new Promise((r) => setTimeout(r, 200)); // the RATE_LIMITED row is written off the hot path
    const logged = await sqliteGet<{ n: number }>(h.dbPath, "SELECT COUNT(*) AS n FROM agent_logs WHERE status = 'RATE_LIMITED'");
    assert.equal(logged?.n, 1, "one RATE_LIMITED row per caller per window, not one per request");
  });
});

// ---------------------------------------------------------------------------
// 4. Signed mobile approval links
// ---------------------------------------------------------------------------
describe("4. HMAC-signed approval callback links", () => {
  const secret = "a".repeat(64);

  test("unit: valid signature verifies; every tampered field is rejected", () => {
    const fields = { id: 42, decision: "APPROVE" as const, exp: Date.now() + 60_000, queuedAt: "2026-11-06T10:00:00.000Z" };
    const sig = signApprovalLink(secret, fields);
    assert.deepEqual(verifyApprovalLink(secret, fields, sig), { ok: true });

    const bad = (f: typeof fields, s = sig) => verifyApprovalLink(secret, f, s);
    assert.equal(bad({ ...fields, id: 43 }).ok, false);
    assert.equal(bad({ ...fields, decision: "REJECT" as unknown as "APPROVE" }).ok, false);
    assert.equal(bad({ ...fields, exp: fields.exp + 1 }).ok, false);
    assert.equal(bad({ ...fields, queuedAt: "2026-11-06T10:00:00.001Z" }).ok, false);
    const flipChar = (s: string, i: number) => s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
    assert.equal(bad(fields, flipChar(sig, 10)).ok, false, "a changed signature byte is rejected");
    for (const c of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") {
      const variant = sig.slice(0, -1) + c;
      if (variant !== sig) assert.equal(bad(fields, variant).ok, false, "non-canonical / altered last character is rejected");
    }
    assert.equal(bad(fields, "").ok, false);
    assert.equal(verifyApprovalLink("b".repeat(64), fields, sig).ok, false, "wrong key");

    const expired = { ...fields, exp: Date.now() - 1 };
    assert.deepEqual(verifyApprovalLink(secret, expired, signApprovalLink(secret, expired)), { ok: false, reason: "expired" });
  });

  test("HTTP: GET is side-effect free; tampered POSTs are refused; valid POST decides", async () => {
    const h = await makeHarness({ rules: REFUND_RULES });
    const queued = await postJson(`${h.base}/api/refund`, { order: { refund: { amount: 300 } } });
    const { approvalId } = (await queued.json()) as { approvalId: number };

    const secretRow = await sqliteGet<{ value: string }>(h.dbPath, "SELECT value FROM system_settings WHERE key = 'approval_signing_secret'");
    const queuedRow = await sqliteGet<{ timestamp: string; status: string }>(h.dbPath, "SELECT timestamp, status FROM pending_actions WHERE id = ?", [approvalId]);
    assert.ok(secretRow && queuedRow);
    const exp = Date.now() + 10 * 60_000;
    const approveUrl = buildApprovalLink(h.base, secretRow.value, { id: approvalId, decision: "APPROVE", exp, queuedAt: queuedRow.timestamp });
    const rejectUrl = buildApprovalLink(h.base, secretRow.value, { id: approvalId, decision: "REJECT", exp, queuedAt: queuedRow.timestamp });
    const status = async () =>
      (await sqliteGet<{ status: string }>(h.dbPath, "SELECT status FROM pending_actions WHERE id = ?", [approvalId]))?.status;

    // A chat app's link preview fetching the URL must not approve anything.
    const preview = await fetch(approveUrl);
    assert.equal(preview.status, 200);
    assert.match(await preview.text(), /Approve this AI agent request/);
    assert.equal(await status(), "PENDING");

    const form = (url: string, override: Record<string, string> = {}) => {
      const u = new URL(url);
      const body = new URLSearchParams({ d: u.searchParams.get("d") ?? "", exp: u.searchParams.get("exp") ?? "", sig: u.searchParams.get("sig") ?? "", ...override });
      return fetch(`${u.origin}${u.pathname}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, redirect: "manual" });
    };

    const rejectSig = new URL(rejectUrl).searchParams.get("sig") ?? "";
    assert.equal((await form(approveUrl, { sig: rejectSig })).status, 403, "a REJECT signature cannot approve");
    assert.equal((await form(approveUrl, { exp: String(exp + 60_000) })).status, 403, "extending the expiry breaks the signature");
    assert.equal((await form(approveUrl, { sig: "x".repeat(43) })).status, 403);
    const otherId = approveUrl.replace(`/approvals/${approvalId}/`, `/approvals/${approvalId + 1}/`);
    assert.equal((await form(otherId)).status, 403, "a link for one action cannot act on another");
    assert.equal(await status(), "PENDING");
    assert.equal(h.hits.get("POST /api/refund") ?? 0, 0);

    const ok = await form(rejectUrl);
    assert.equal(ok.status, 200);
    assert.equal(await status(), "REJECTED");
    assert.equal((await form(approveUrl)).status, 409, "decided actions cannot be decided again via a link");
    assert.equal(h.hits.get("POST /api/refund") ?? 0, 0, "nothing executed");
  });
});
