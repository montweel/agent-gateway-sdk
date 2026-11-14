/**
 * v2.2 compliance audit trail: end-user attribution, approver attribution, redacted response
 * capture sealed into the hash chain, configurable redact keys.
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import fs from "fs";
import http from "http";
import path from "path";
import express from "express";
import type { Request, Response } from "express";
import { GENESIS_HASH, computeRowHash } from "../src/core/auditLedger";
import { cleanEndUser, endUserOf } from "../src/core/payloadCapture";
import { closeServer, listen, makeHarness, onCleanup, postJson, runCleanups, sqliteAll, sqliteGet, sqliteRun, tempDir, waitFor } from "./helpers";

after(runCleanups);

interface LogDbRow {
  id: number;
  status: string;
  end_user: string | null;
  approved_by: string | null;
  response_payload: string | null;
  response_pending: number | null;
  request_snapshot: string | null;
  row_hash: string | null;
}

/** A fake upstream that answers with secrets; `slow` requests wait until released. */
async function fakeUpstream() {
  const seen: http.IncomingHttpHeaders[] = [];
  let release: () => void = () => undefined;
  const gate = new Promise<void>((r) => (release = r));
  const app = express();
  app.use(express.json());
  app.post("/api/orders", async (req: Request, res: Response) => {
    seen.push(req.headers);
    if ((req.body as { slow?: boolean }).slow) await gate;
    res.json({ order: 7, api_token: "tok-should-hide", customer_ref: "C-99", note: "paid with 4111 1111 1111 1111" });
  });
  const server = http.createServer(app);
  const port = await listen(server);
  onCleanup(() => closeServer(server));
  return { url: `http://127.0.0.1:${port}`, seen, release: () => release() };
}

async function proxyHarness(upstreamUrl: string, audit: Record<string, unknown> = { capturePayloads: true, redactKeys: ["customer_ref"] }) {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ targetUrl: upstreamUrl, rateLimitPerMinute: 1000, audit }));
  onCleanup(async () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  return makeHarness({ dir, rules: { "POST /api/orders": { mode: "ALLOW", description: "" } } });
}

describe("compliance audit trail", () => {
  test("hash: rows without attribution hash exactly as before, so older ledgers still verify", () => {
    const row = {
      id: 1,
      timestamp: "2026-01-01T00:00:00.000Z",
      method: "GET",
      path: "/api/x",
      status: "ALLOWED",
      user_agent: null,
      agent_key: null,
      action_id: null,
      caller_ip: "1.2.3.4",
      detail: null,
      amount: null,
      workspace_id: 1,
      shadow: null,
      request_snapshot: null,
      original_payload: null,
      modified_payload: null,
    };
    const legacy = crypto
      .createHash("sha256")
      .update(`${GENESIS_HASH}\n${JSON.stringify([1, row.timestamp, "|1.2.3.4", "GET /api/x", "ALLOWED", [null, null], null, 1, null, null, null, null, null])}`, "utf8")
      .digest("hex");
    assert.equal(computeRowHash(GENESIS_HASH, { ...row, end_user: null, approved_by: null, response_payload: null }), legacy);
    assert.notEqual(computeRowHash(GENESIS_HASH, { ...row, end_user: "alice" }), legacy, "attribution is covered by the hash");
    assert.notEqual(computeRowHash(GENESIS_HASH, { ...row, approved_by: "alice" }), computeRowHash(GENESIS_HASH, { ...row, end_user: "alice" }));
  });

  test("cleanEndUser: trims, strips control characters, masks secrets", () => {
    assert.equal(cleanEndUser("  alice@corp.example "), "alice@corp.example");
    assert.equal(cleanEndUser("eve\u0007 Bearer abcdefghijklmnop"), "eve [REDACTED:secret]");
    assert.equal(cleanEndUser("   "), null);
    assert.equal(cleanEndUser(undefined), null);
  });

  test("endUserOf: verified only with SSO trust on AND the matching shared secret", () => {
    const secret = "s".repeat(64);
    const headers = (h: Record<string, string>) => (name: string) => h[name];
    const cfg = { ssoTrustProxyHeader: true, ssoSharedSecret: secret, ssoUserHeader: "x-forwarded-user" };
    assert.deepEqual(endUserOf(headers({ "x-forwarded-user": "alice", "x-gateway-sso-secret": secret }), cfg), { endUser: "alice", verified: true });
    assert.deepEqual(endUserOf(headers({ "x-forwarded-user": "alice", "x-gateway-sso-secret": "wrong" }), cfg), { endUser: "alice", verified: false });
    assert.deepEqual(endUserOf(headers({ "x-forwarded-user": "alice" }), cfg), { endUser: "alice", verified: false });
    assert.deepEqual(
      endUserOf(headers({ "x-forwarded-user": "alice", "x-gateway-sso-secret": secret }), { ...cfg, ssoTrustProxyHeader: false }),
      { endUser: "alice", verified: false },
      "SSO trust off: the secret proves nothing"
    );
    assert.deepEqual(endUserOf(headers({ "x-forwarded-user": "a", "x-gateway-sso-secret": "" }), { ...cfg, ssoSharedSecret: "" }).verified, false);
    assert.deepEqual(endUserOf(headers({ "x-sso-user": "bob" }), { ...cfg, ssoUserHeader: "x-sso-user" }).endUser, "bob", "the configured SSO user header is used");
  });

  test("verified vs agent-claimed end users are stored, returned, hashed, and survive approval", async () => {
    const secret = "f".repeat(64);
    const dir = tempDir();
    fs.writeFileSync(
      path.join(dir, "config.json"),
      JSON.stringify({ targetUrl: "", rateLimitPerMinute: 1000, ssoTrustProxyHeader: true, ssoSharedSecret: secret })
    );
    onCleanup(async () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const h = await makeHarness({ dir, rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" }, "GET /api/ping": { mode: "ALLOW", description: "" } } });

    await fetch(`${h.base}/api/ping`, { headers: { "x-forwarded-user": "proxy-alice", "x-gateway-sso-secret": secret } });
    await fetch(`${h.base}/api/ping`, { headers: { "x-forwarded-user": "claimed-mallory" } });
    const q = (await (await postJson(`${h.base}/api/refund`, { amount: 5 }, { "x-forwarded-user": "proxy-carol", "x-gateway-sso-secret": secret })).json()) as { approvalId: number };
    assert.equal((await h.admin("POST", `/approvals/${q.approvalId}/decide`, { decision: "APPROVE" })).status, 200);

    type Row = { id: number; end_user: string; end_user_verified: number | null; status: string; request_snapshot: string | null };
    const rows = await waitFor(
      async () => {
        const r = await sqliteAll<Row & { row_hash: string | null }>(h.dbPath, "SELECT id, end_user, end_user_verified, status, request_snapshot, row_hash FROM agent_logs ORDER BY id");
        return r.length === 4 && r.every((x) => x.row_hash) ? r : null;
      },
      8000,
      "four sealed rows"
    );
    const byUser = (u: string, status: string) => rows.find((r) => r.end_user === u && r.status === status)!;
    assert.equal(byUser("proxy-alice", "ALLOWED").end_user_verified, 1);
    assert.equal(byUser("claimed-mallory", "ALLOWED").end_user_verified, 0);
    assert.equal(byUser("proxy-carol", "QUEUED").end_user_verified, 1);
    assert.equal(byUser("proxy-carol", "APPROVED").end_user_verified, 1, "verification follows the action to its decision row");
    assert.ok(rows.every((r) => !(r.request_snapshot ?? "").includes(secret)), "the SSO secret is never stored");

    const list = (await h.admin("GET", "/logs")).data as Array<{ end_user: string; end_user_verified: boolean }>;
    assert.equal(list.find((r) => r.end_user === "proxy-alice")!.end_user_verified, true);
    assert.equal(list.find((r) => r.end_user === "claimed-mallory")!.end_user_verified, false);
    const detail = (await h.admin("GET", `/logs/${byUser("claimed-mallory", "ALLOWED").id}`)).data;
    assert.equal(detail.end_user_verified, false);

    const csv = await (await fetch(`${h.base}/api/agent-admin/logs/export.csv`, { headers: { "x-admin-token": "v12-suite-admin-token-0123456789abcdef" } })).text();
    assert.match(csv, /proxy-alice,verified,/);
    assert.match(csv, /claimed-mallory,agent-claimed,/);

    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true);
    // Upgrading an agent's claim to "verified" by hand breaks the chain.
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET end_user_verified = 1 WHERE end_user = 'claimed-mallory'");
    const v = (await h.admin("GET", "/audit/verify")).data;
    assert.equal(v.ok, false);
    assert.equal(v.brokenAt, byUser("claimed-mallory", "ALLOWED").id);
  });

  test("proxy mode: end user + redacted request and response are stored, sealed and verifiable", async () => {
    const up = await fakeUpstream();
    const h = await proxyHarness(up.url);

    const res = await postJson(`${h.base}/api/orders`, { item: "x", password: "hunter2", customer_ref: "C-1" }, { "x-forwarded-user": "alice@corp.example" });
    assert.equal(res.status, 200);
    const agentSaw = (await res.json()) as Record<string, unknown>;
    assert.equal(agentSaw.api_token, "tok-should-hide", "redaction applies to what is stored, never to what the agent receives");
    assert.equal(up.seen[0]["x-forwarded-user"], undefined, "the end-user header is not forwarded upstream");

    const row = await waitFor(
      async () => (await sqliteGet<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE status = 'ALLOWED' AND row_hash IS NOT NULL")) ?? null,
      8000,
      "sealed ALLOWED row"
    );
    assert.equal(row.end_user, "alice@corp.example");
    assert.equal(row.response_pending, null);
    const stored = row.response_payload ?? "";
    for (const secret of ["tok-should-hide", "C-99", "4111"]) assert.ok(!stored.includes(secret), `response must not store ${secret}`);
    for (const secret of ["hunter2", '"C-1"']) assert.ok(!(row.request_snapshot ?? "").includes(secret), `request must not store ${secret}`);

    const detail = (await h.admin("GET", `/logs/${row.id}`)).data;
    assert.equal(detail.end_user, "alice@corp.example");
    assert.equal(detail.request.body.password, "[REDACTED]");
    assert.equal(detail.request.body.customer_ref, "[REDACTED]", "custom redact key");
    assert.equal(detail.response.status, 200);
    assert.equal(detail.response.body.api_token, "[REDACTED]");
    assert.equal(detail.response.body.customer_ref, "[REDACTED]");
    assert.equal(detail.response.body.order, 7);
    assert.equal(detail.row_hash, row.row_hash);

    const list = (await h.admin("GET", "/logs")).data as Array<Record<string, unknown>>;
    const listed = list.find((r) => r.id === row.id)!;
    assert.equal(listed.end_user, "alice@corp.example");
    assert.equal(listed.has_response, true);
    assert.ok(!("response_payload" in listed), "list responses stay lean");

    assert.equal((await h.admin("GET", "/logs/999999")).status, 404);
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true);

    // Tampering with the captured response or the attribution breaks the chain.
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET response_payload = replace(response_payload, '\"order\":7', '\"order\":8') WHERE id = ?", [row.id]);
    const broken = (await h.admin("GET", "/audit/verify")).data;
    assert.equal(broken.ok, false);
    assert.equal(broken.brokenAt, row.id);
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET response_payload = ? WHERE id = ?", [row.response_payload, row.id]);
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true);
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET end_user = 'mallory' WHERE id = ?", [row.id]);
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, false);
  });

  test("the ledger waits for an in-flight response, keeping rows in order, then seals both", async () => {
    const up = await fakeUpstream();
    const h = await proxyHarness(up.url);

    const slow = postJson(`${h.base}/api/orders`, { slow: true });
    const first = await waitFor(async () => (await sqliteGet<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE status = 'ALLOWED' ORDER BY id LIMIT 1")) ?? null, 8000, "slow row");
    assert.equal((await postJson(`${h.base}/api/orders`, { fast: true })).status, 200);
    // The fast response has landed, but its row sits behind the pending one: neither is sealed.
    await waitFor(async () => (await sqliteGet<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE id > ? AND response_payload IS NOT NULL", [first.id])) ?? null, 8000, "fast response");
    await new Promise((r) => setTimeout(r, 1500)); // > one sealer tick (1 s)
    const before = await sqliteAll<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE status = 'ALLOWED' ORDER BY id");
    assert.equal(before.length, 2);
    assert.ok(before.every((r) => r.row_hash === null), "nothing is sealed past a row still waiting for its response");
    assert.equal(before[0].response_pending, 1);

    up.release();
    assert.equal((await slow).status, 200);
    const after = await waitFor(
      async () => {
        const rows = await sqliteAll<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE status = 'ALLOWED' ORDER BY id");
        return rows.every((r) => r.row_hash !== null) ? rows : null;
      },
      8000,
      "both rows sealed"
    );
    assert.ok(after[0].response_payload?.includes('"order":7'));
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true);
  });

  test("capturePayloads off: no response stored and nothing held back; config is validated", async () => {
    const up = await fakeUpstream();
    const h = await proxyHarness(up.url);
    assert.equal((await h.admin("POST", "/config", { audit: { redactKeys: "nope" } })).status, 400);
    assert.equal((await h.admin("POST", "/config", { audit: { capturePayloads: "yes" } })).status, 400);
    const saved = await h.admin("POST", "/config", { audit: { capturePayloads: false } });
    assert.equal(saved.status, 200);
    assert.deepEqual(saved.data.config.audit, { capturePayloads: false, redactKeys: ["customer_ref"] });

    assert.equal((await postJson(`${h.base}/api/orders`, { item: 1 })).status, 200);
    const row = await waitFor(
      async () => (await sqliteGet<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE status = 'ALLOWED' AND row_hash IS NOT NULL")) ?? null,
      8000,
      "sealed row"
    );
    assert.equal(row.response_payload, null);
    assert.equal(row.response_pending, null);
  });

  test("approval: end user carried from the queued request, approver and replay response recorded", async () => {
    const h = await makeHarness({ rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } } });
    const queued = await postJson(`${h.base}/api/refund`, { amount: 40, password: "pw-secret" }, { "x-forwarded-user": "bob" });
    assert.equal(queued.status, 202);
    const { approvalId } = (await queued.json()) as { approvalId: number };

    const decided = await h.admin("POST", `/approvals/${approvalId}/decide`, { decision: "APPROVE" });
    assert.equal(decided.status, 200);
    const approver = decided.data.decided_by as string;
    assert.ok(approver);

    const rows = await waitFor(
      async () => {
        const r = await sqliteAll<LogDbRow>(h.dbPath, "SELECT * FROM agent_logs WHERE action_id = ? ORDER BY id", [approvalId]);
        return r.length === 2 && r.every((x) => x.row_hash !== null) ? r : null;
      },
      8000,
      "queued + approved rows sealed"
    );
    const [q, a] = rows;
    assert.equal(q.status, "QUEUED");
    assert.equal(q.end_user, "bob");
    assert.equal(q.approved_by, null);
    assert.equal(a.status, "APPROVED");
    assert.equal(a.end_user, "bob", "end user follows the action to its decision row");
    assert.equal(a.approved_by, approver);
    const response = JSON.parse(a.response_payload ?? "null") as { status: number; body: { executed: string } };
    assert.equal(response.status, 200);
    assert.equal(response.body.executed, "POST /api/refund");
    // The replay to the host app is internal: it does not add an ALLOWED row of its own.
    assert.equal((await sqliteAll(h.dbPath, "SELECT id FROM agent_logs WHERE status = 'ALLOWED'")).length, 0);
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true);
  });
});
