/**
 * v2.0 Commercial & Enterprise Engine suite.
 *
 *   1. Ed25519 offline licensing (MONT-V2 keys, tiers, expiry, tamper, keygen CLI, feature gates)
 *   2. Multi-tenant workspaces (routing, isolation, keys, budgets, modes, chat routing, plan limits)
 *   3. Edit & Approve (HTTP body + query, MCP arguments, redaction-safe merge, audit)
 *   4. Tamper-evident hash-chained audit ledger (verify, tampering, deletion, retention, multi-process)
 *   5. Shadow mode + Policy Time-Machine replay
 *   6. Outbound response guard (middleware + proxy + MCP) and the legacy MCP HTTP+SSE transport
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "child_process";
import crypto from "crypto";
import fs from "fs";
import http from "http";
import path from "path";
import express from "express";
import type { Request, Response } from "express";
import { TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, testLicense } from "./testLicense";
import {
  ADMIN_TOKEN,
  closeServer,
  fakeTelegram,
  listen,
  makeHarness,
  onCleanup,
  pendingStatus,
  postJson,
  runCleanups,
  sleep,
  sqliteAll,
  sqliteGet,
  sqliteRun,
  tempDir,
  waitFor,
} from "./helpers";
import { createMcpHttpProxy, inspectResponseBody, parseSse, signLicenseV2, verifyLicenseKey } from "../src/gateway";
import type { Rules } from "../src/gateway";
import { createDatabase } from "../src/core/db";
import { computeRowHash, createAuditLedger, GENESIS_HASH } from "../src/core/auditLedger";
import { applyEdits } from "../src/core/payloadPatch";
import { splitWorkspacePath } from "../src/core/workspaces";

after(runCleanups);

const DAY = 24 * 3600_000;

/** A fake upstream API that records what reached it. */
async function fakeUpstream(): Promise<{ base: string; hits: Array<{ method: string; url: string; body: unknown; headers: http.IncomingHttpHeaders; raw: string }>; respond: (fn: (req: Request, res: Response) => void) => void }> {
  const hits: Array<{ method: string; url: string; body: unknown; headers: http.IncomingHttpHeaders; raw: string }> = [];
  let responder: ((req: Request, res: Response) => void) | null = null;
  const app = express();
  app.use(express.text({ type: "*/*" }));
  app.all(/.*/, (req: Request, res: Response) => {
    const raw = typeof req.body === "string" ? req.body : "";
    let body: unknown = null;
    try {
      body = raw ? JSON.parse(raw) : null;
    } catch {
      body = raw;
    }
    hits.push({ method: req.method, url: req.originalUrl, body, headers: req.headers, raw });
    if (responder) return responder(req, res);
    res.json({ ok: true, via: "upstream", url: req.originalUrl });
  });
  const server = http.createServer(app);
  const port = await listen(server);
  onCleanup(() => closeServer(server));
  return { base: `http://127.0.0.1:${port}`, hits, respond: (fn) => (responder = fn) };
}

function call(base: string, method: string, p: string, body?: unknown, headers: Record<string, string> = {}): Promise<globalThis.Response> {
  return fetch(`${base}${p}`, {
    method,
    headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// ===========================================================================
// 1. Licensing
// ===========================================================================
describe("1. Ed25519 offline license enforcement", () => {
  test("MONT-V2 keys: sign, verify, tiers, expiry, tamper and version binding", () => {
    const key = testLicense("AGENCY", { maxWorkspaces: 20, orgName: "Acme Automation" });
    assert.match(key, /^MONT-V2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const v = verifyLicenseKey(key);
    assert.ok(v.ok);
    if (!v.ok) return;
    assert.equal(v.payload.tier, "AGENCY");
    assert.equal(v.payload.maxWorkspaces, 20);
    assert.equal(v.payload.org, "Acme Automation");
    assert.equal(v.payload.version, 2);

    const [, payload, sig] = key.split(".");
    // Tampered payload (raise maxWorkspaces) -> signature fails.
    const forged = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    forged.maxWorkspaces = 9999;
    const forgedKey = `MONT-V2.${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${sig}`;
    assert.equal(verifyLicenseKey(forgedKey).ok, false);
    // Flipped signature bit.
    const badSig = Buffer.from(sig, "base64url");
    badSig[0] ^= 1;
    assert.equal(verifyLicenseKey(`MONT-V2.${payload}.${badSig.toString("base64url")}`).ok, false);
    // Signed by another key.
    const other = crypto.generateKeyPairSync("ed25519").privateKey;
    assert.equal(verifyLicenseKey(signLicenseV2({ tier: "AGENCY", orgName: "x", maxWorkspaces: 5, expiresAt: Date.now() + DAY }, other)).ok, false);
    // A v1-style signature (over the bare payload) does not validate as v2: the version is bound into the signature.
    const v1Sig = crypto.sign(null, Buffer.from(payload), TEST_PRIVATE_KEY).toString("base64url");
    assert.equal(verifyLicenseKey(`MONT-V2.${payload}.${v1Sig}`).ok, false);
    // Malformed pieces.
    assert.equal(verifyLicenseKey("MONT-V2.only-one-part").ok, false);
    assert.equal(verifyLicenseKey(`MONT-V2.${payload}.${sig}.extra`).ok, false);
    assert.equal(verifyLicenseKey("not a key").ok, false);
  });

  test("Community gates: workspaces, Edit & Approve and ledger verification need a key; activation unlocks instantly; expiry relocks", async () => {
    const h = await makeHarness({
      license: null,
      rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } },
    });
    // Fresh anchor = the 7-day Pro trial. Expire it to get Community.
    const expired = await h.admin("POST", "/license/simulate-trial-expiry?state=expired");
    assert.equal(expired.data.tier, "COMMUNITY");
    assert.equal(expired.data.maxWorkspaces, 1);
    assert.equal(expired.data.features.payloadPatching, false);

    const create = await h.admin("POST", "/workspaces", { name: "Acme" });
    assert.equal(create.status, 402);
    assert.equal(create.data.proRequired, true);
    assert.equal((await h.admin("GET", "/audit/verify")).status, 402);

    const queued = await (await call(h.base, "POST", "/api/refund", { amount: 250 })).json();
    const edit = await h.admin("POST", `/approvals/${queued.approvalId}/decide`, { decision: "APPROVE", modifiedBody: { amount: 50 } });
    assert.equal(edit.status, 402);
    assert.equal(await pendingStatus(h.dbPath, queued.approvalId), "PENDING", "a refused edit changes nothing");
    // Community still has local approvals.
    assert.equal((await h.admin("POST", `/approvals/${queued.approvalId}/decide`, { decision: "APPROVE" })).status, 200);

    // Activate an AGENCY key from the dashboard API: everything unlocks without a restart.
    const act = await h.admin("POST", "/license", { licenseKey: testLicense("AGENCY", { maxWorkspaces: 3 }) });
    assert.equal(act.status, 200);
    assert.equal(act.data.tier, "AGENCY");
    assert.equal(act.data.keyVersion, 2);
    assert.equal(act.data.features.multiWorkspace, true);
    assert.equal((await h.admin("POST", "/workspaces", { name: "Acme" })).status, 201);
    assert.equal((await h.admin("GET", "/audit/verify")).status, 200);

    // An expired key falls back to Community (and says why).
    const old = signLicenseV2({ tier: "AGENCY", orgName: "Old", maxWorkspaces: 3, expiresAt: Date.now() - DAY, iat: Date.now() - 30 * DAY }, TEST_PRIVATE_KEY);
    const st = await h.admin("POST", "/license", { licenseKey: old });
    assert.equal(st.data.tier, "COMMUNITY");
    assert.equal(st.data.expired, true);
    assert.equal((await h.admin("GET", "/audit/verify")).status, 402);
    // A bad key is refused outright.
    assert.equal((await h.admin("POST", "/license", { licenseKey: "MONT-V2.abc.def" })).status, 400);
  });

  test("scripts/keygen.ts signs keys the gateway accepts (zero network)", async () => {
    const priv = TEST_PRIVATE_KEY.export({ format: "der", type: "pkcs8" }).toString("base64url");
    const run = (args: string[]): Promise<{ code: number; stdout: string; stderr: string }> =>
      new Promise((resolve) => {
        execFile(process.execPath, ["--import", "tsx", path.join(__dirname, "..", "scripts", "keygen.ts"), ...args], { env: { ...process.env, MONT_PUBLIC_KEY: TEST_PUBLIC_KEY } }, (err, stdout, stderr) =>
          resolve({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout, stderr })
        );
      });
    const signed = await run(["sign", "--tier=AGENCY", '--org=Keygen Agency', "--max-workspaces=12", "--days=10", `--key=${priv}`]);
    assert.equal(signed.code, 0, signed.stderr);
    const key = signed.stdout.trim();
    const v = verifyLicenseKey(key);
    assert.ok(v.ok && v.payload.maxWorkspaces === 12 && v.payload.tier === "AGENCY");
    const checked = await run(["verify", key]);
    assert.equal(checked.code, 0, checked.stderr);
    assert.equal(JSON.parse(checked.stdout).orgName, "Keygen Agency");
    const bad = await run(["sign", "--tier=GOLD", "--org=x", `--key=${priv}`]);
    assert.notEqual(bad.code, 0);
  });
});

// ===========================================================================
// 2. Workspaces
// ===========================================================================
const REFUND_RULES = (max: number): Rules => ({
  "POST /api/refund": {
    mode: "REQUIRE_APPROVAL",
    description: "refunds",
    policies: [{ name: "small", when: [{ field: "body.amount", op: "<=", value: max }], mode: "ALLOW" }],
    budget: { field: "body.amount", max: 100, windowMinutes: 60, per: "global", onExceed: "BLOCK" },
  },
  "GET /api/orders": { mode: "ALLOW", description: "" },
});

describe("2. Multi-tenant workspaces", () => {
  test("routing (path / header / bearer), isolation of rules, budgets, upstreams, keys and modes", async () => {
    const globexUp = await fakeUpstream();
    const h = await makeHarness({ rules: { "GET /api/orders": { mode: "ALLOW", description: "default ws" } } });

    const acme = await h.admin("POST", "/workspaces", { name: "Acme Outfitters" });
    assert.equal(acme.status, 201);
    assert.equal(acme.data.workspace.slug, "acme-outfitters");
    assert.match(acme.data.apiKey, /^mws_/);
    const acmeKey: string = acme.data.apiKey;
    const globex = await h.admin("POST", "/workspaces", { name: "Globex", slug: "globex", upstreamUrl: globexUp.base });
    const globexKey: string = globex.data.apiKey;
    assert.equal((await h.admin("POST", "/workspaces", { name: "Dup", slug: "globex" })).status, 400);
    assert.equal((await h.admin("POST", "/workspaces", { name: "x", slug: "all" })).status, 400, "reserved slug");

    // Rules per workspace: Acme allows refunds <= 50, Globex <= 80; the default workspace has no refund rule.
    assert.equal((await h.admin("POST", "/rules", REFUND_RULES(50), { "x-mont-workspace": "acme-outfitters" })).status, 200);
    assert.equal((await h.admin("POST", "/rules", REFUND_RULES(80), { "x-mont-workspace": "globex" })).status, 200);
    assert.ok((await h.admin("GET", "/rules", undefined, { "x-mont-workspace": "globex" })).data["POST /api/refund"]);
    assert.equal((await h.admin("GET", "/rules")).data["POST /api/refund"], undefined, "default workspace rules untouched");

    const acmeAuth = { authorization: `Bearer ${acmeKey}` };
    // 1) Path prefix + key: forwarded to the host app WITHOUT the /w/<slug> prefix.
    let r = await call(h.base, "POST", "/api/w/acme-outfitters/refund?ref=1", { amount: 40 }, acmeAuth);
    assert.equal(r.status, 200);
    assert.equal(h.hits[h.hits.length - 1]?.key, "POST /api/refund");
    // 2) Header + key.
    r = await call(h.base, "POST", "/api/refund", { amount: 30 }, { ...acmeAuth, "x-mont-workspace": "acme-outfitters" });
    assert.equal(r.status, 200);
    // 3) Bearer key alone selects the workspace.
    r = await call(h.base, "POST", "/api/refund", { amount: 20 }, acmeAuth);
    assert.equal(r.status, 200);
    // Acme's budget (100) is now 90 used; Globex's budget is untouched (isolation).
    r = await call(h.base, "POST", "/api/refund", { amount: 20 }, acmeAuth);
    assert.equal(r.status, 403, "acme budget exhausted");
    const g = await call(h.base, "POST", "/api/w/globex/refund", { amount: 70 }, { authorization: `Bearer ${globexKey}` });
    assert.equal(g.status, 200, "globex has its own budget and its own threshold (70 <= 80)");
    // Globex forwards to ITS upstream, prefix stripped, and the gateway's mws_ credential is not forwarded.
    const gh = globexUp.hits[globexUp.hits.length - 1];
    assert.equal(gh.url, "/api/refund");
    assert.equal(gh.headers.authorization, undefined);
    assert.deepEqual(gh.body, { amount: 70 });
    // 60 at Acme would need approval (> 50), at Globex it would be allowed: per-workspace thresholds.
    // Default workspace: no refund rule = default deny.
    assert.equal((await call(h.base, "POST", "/api/refund", { amount: 1 })).status, 403);

    // Key enforcement.
    assert.equal((await call(h.base, "POST", "/api/refund", { amount: 1 }, { "x-mont-workspace": "acme-outfitters" })).status, 401, "workspace requires its key");
    assert.equal((await call(h.base, "POST", "/api/refund", { amount: 1 }, { ...acmeAuth, "x-mont-workspace": "globex" })).status, 403, "acme's key cannot act on globex");
    assert.equal((await call(h.base, "POST", "/api/refund", { amount: 1 }, { authorization: "Bearer mws_forged000000000000000000" })).status, 401);
    assert.equal((await call(h.base, "POST", "/api/refund", { amount: 1 }, { "x-mont-workspace": "nope" })).status, 404);
    assert.equal(
      (await call(h.base, "POST", "/api/w/acme-outfitters/refund", { amount: 1 }, { ...acmeAuth, "x-mont-workspace": "globex" })).status,
      400,
      "conflicting selectors"
    );

    // Per-workspace lockdown: only that client stops.
    assert.equal((await h.admin("POST", "/emergency", { mode: "lockdown", reason: "client incident" }, { "x-mont-workspace": "globex" })).status, 200);
    assert.equal((await call(h.base, "GET", "/api/orders", undefined, { authorization: `Bearer ${globexKey}` })).status, 403);
    assert.equal((await call(h.base, "GET", "/api/orders", undefined, acmeAuth)).status, 200, "other clients unaffected");
    assert.equal((await call(h.base, "GET", "/api/orders")).status, 200, "default workspace unaffected");
    assert.equal((await h.admin("GET", "/emergency")).data.mode, "normal", "global switch untouched");
    await h.admin("POST", "/emergency", { mode: "normal" }, { "x-mont-workspace": "globex" });

    // Admin views are scoped.
    const acmeLogs = (await h.admin("GET", "/logs", undefined, { "x-mont-workspace": "acme-outfitters" })).data as any[];
    assert.ok(acmeLogs.length >= 4 && acmeLogs.every((l) => l.workspace_slug === "acme-outfitters"));
    const usage = (await h.admin("GET", "/guards/usage", undefined, { "x-mont-workspace": "acme-outfitters" })).data as any[];
    assert.equal(usage.length, 1);
    assert.equal(usage[0].spent, 90);
    const overview = (await h.admin("GET", "/workspaces/overview")).data;
    assert.equal(overview.workspaces.length, 3);
    const acmeRow = overview.workspaces.find((w: any) => w.workspace.slug === "acme-outfitters");
    assert.equal(acmeRow.counts.ALLOWED, 4, "3 refunds + 1 order lookup");
    assert.ok(acmeRow.moneyProtected >= 20);

    // Rotating a key revokes the old one at once.
    const rotated = await h.admin("POST", "/workspaces/acme-outfitters/rotate-key");
    assert.equal((await call(h.base, "GET", "/api/orders", undefined, acmeAuth)).status, 401);
    assert.equal((await call(h.base, "GET", "/api/orders", undefined, { authorization: `Bearer ${rotated.data.apiKey}` })).status, 200);
    // Deleting the default workspace is refused.
    assert.equal((await h.admin("DELETE", "/workspaces/default")).status, 400);
  });

  test("plan limits: creation is capped, and a downgrade refuses the newest client (fail closed)", async () => {
    const h = await makeHarness({ license: testLicense("AGENCY", { maxWorkspaces: 3 }), rules: {} });
    const a = await h.admin("POST", "/workspaces", { name: "A", requireKey: false });
    const b = await h.admin("POST", "/workspaces", { name: "B", requireKey: false });
    assert.equal(a.status, 201);
    assert.equal(b.status, 201);
    const c = await h.admin("POST", "/workspaces", { name: "C" });
    assert.equal(c.status, 402, "default + 2 clients = the 3 the license covers");
    for (const slug of ["a", "b"]) await h.admin("POST", "/rules", { "GET /api/ping": true }, { "x-mont-workspace": slug });
    assert.equal((await call(h.base, "GET", "/api/ping", undefined, { "x-mont-workspace": "b" })).status, 200);

    // Downgrade: a 2-workspace key now. The OLDEST client keeps working, the newest is refused.
    await h.gateway.close();
    const h2 = await makeHarness({ dir: h.dir, license: testLicense("PRO", { maxWorkspaces: 2 }) });
    assert.equal((await call(h2.base, "GET", "/api/ping", undefined, { "x-mont-workspace": "a" })).status, 200);
    const refused = await call(h2.base, "GET", "/api/ping", undefined, { "x-mont-workspace": "b" });
    assert.equal(refused.status, 402);
    assert.match((await refused.json()).message, /beyond this installation's license/);
    const list = (await h2.admin("GET", "/workspaces")).data;
    assert.equal(list.workspaces.find((w: any) => w.slug === "b").entitled, false);
  });

  test("approval routing: each client's Telegram chat gets its own approvals and can only decide those", async () => {
    const token = "1234567:AAHtestTokenForMontWorkspaceRoutingSuite";
    const tg = await fakeTelegram(token);
    const h = await makeHarness({
      rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } },
      gatewayOptions: { telegramApiBase: tg.base, telegramPollTimeoutSec: 0 },
    });
    await h.admin("POST", "/setup", { notifications: { telegram: { enabled: true, mode: "polling", botToken: token, chatId: "-100111" } } });
    const ws = await h.admin("POST", "/workspaces", { name: "Acme", slug: "acme", telegramChatId: "-100222", requireKey: false });
    assert.equal(ws.status, 201);
    await h.admin("POST", "/rules", { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } }, { "x-mont-workspace": "acme" });

    const q = await (await call(h.base, "POST", "/api/w/acme/refund", { amount: 75 })).json();
    const msg = await waitFor(() => tg.sent.find((m) => String(m.text).includes(`#${q.approvalId}`)), 5000, "acme notification");
    assert.equal(String(msg.chat_id), "-100222", "routed to the client's chat");
    assert.match(String(msg.text), /\[Acme\]/);
    const approveToken = msg.reply_markup.inline_keyboard[0][0].callback_data as string;

    // Tapped from the agency's global chat: refused, still pending.
    tg.push({ callback_query: { id: "cq1", data: approveToken, from: { id: 5, username: "boss" }, message: { message_id: 1, chat: { id: -100111 } } } });
    await waitFor(() => tg.calls.find((c) => c.method === "sendMessage" && String(c.body.text).includes("belongs to another client")), 5000, "refusal");
    assert.equal(await pendingStatus(h.dbPath, q.approvalId), "PENDING");
    // From the client's own chat: approved and executed.
    tg.push({ callback_query: { id: "cq2", data: approveToken, from: { id: 6, username: "acme_owner" }, message: { message_id: 2, chat: { id: -100222 } } } });
    await waitFor(async () => (await pendingStatus(h.dbPath, q.approvalId)) === "APPROVED", 5000, "approved from acme chat");

    // /lockdown in the client's chat locks down only that client.
    tg.push({ message: { message_id: 3, text: "/lockdown fraud spike", from: { id: 6 }, chat: { id: -100222 } } });
    await waitFor(async () => (await h.admin("GET", "/emergency", undefined, { "x-mont-workspace": "acme" })).data.mode === "lockdown", 5000, "acme lockdown");
    assert.equal((await h.admin("GET", "/emergency")).data.mode, "normal");
  });
});

// ===========================================================================
// 3. Edit & Approve
// ===========================================================================
describe("3. Human-in-the-loop Edit & Approve", () => {
  test("merge keeps the real values behind redacted fields", () => {
    const original = { amount: 250, email: "jane@example.com", items: [{ sku: "A", qty: 1 }], token: "sk_live_abcdefghijklmnop" };
    const shown = { amount: 250, email: "j***@example.com", items: [{ sku: "A", qty: 1 }], token: "[REDACTED]" };
    const edited = { amount: 50, email: "j***@example.com", items: [{ sku: "A", qty: 1 }, { sku: "B", qty: 2 }], token: "[REDACTED]", note: "reduced" };
    assert.deepEqual(applyEdits(original, shown, edited), {
      amount: 50,
      email: "jane@example.com",
      items: [{ sku: "A", qty: 1 }, { sku: "B", qty: 2 }],
      token: "sk_live_abcdefghijklmnop",
      note: "reduced",
    });
    assert.throws(() => applyEdits({}, {}, JSON.parse('{"__proto__": {"x": 1}}')));
  });

  test("HTTP: the approver lowers a hallucinated refund; the edited body is forwarded with a fresh Content-Length and both payloads are audited", async () => {
    const up = await fakeUpstream();
    const h = await makeHarness({
      rules: {
        "POST /api/refund": {
          mode: "REQUIRE_APPROVAL",
          description: "",
          policies: [{ name: "huge", when: [{ field: "body.amount", op: ">", value: 1000 }], mode: "BLOCK" }],
        },
      },
    });
    await h.admin("POST", "/workspaces", { name: "Shop", slug: "shop", upstreamUrl: up.base, requireKey: false });
    await h.admin("POST", "/rules", { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "", policies: [{ name: "huge", when: [{ field: "body.amount", op: ">", value: 1000 }], mode: "BLOCK" }] } }, { "x-mont-workspace": "shop" });

    const body = { orderId: "#1001", amount: 250, email: "jane@example.com", reason: "agent thinks the item was missing" };
    const q = await (await call(h.base, "POST", "/api/w/shop/refund?priority=low&token=SECRETQUERY", body)).json();
    assert.equal(q.status, "PENDING_APPROVAL");
    const row = ((await h.admin("GET", "/approvals", undefined, { "x-mont-workspace": "shop" })).data as any[]).find((a) => a.id === q.approvalId);
    const shown = JSON.parse(row.body);
    assert.equal(shown.email, "j***@example.com", "the approver only sees the masked email");

    // An edit that crosses a hard BLOCK tier is refused; the request stays pending.
    const tooBig = await h.admin("POST", `/approvals/${q.approvalId}/decide`, { decision: "APPROVE", modifiedBody: { ...shown, amount: 5000 } });
    assert.equal(tooBig.status, 409);
    assert.equal(await pendingStatus(h.dbPath, q.approvalId), "PENDING");
    // Bad edits.
    assert.equal((await h.admin("POST", `/approvals/${q.approvalId}/decide`, { decision: "REJECT", modifiedBody: shown })).status, 400);
    assert.equal((await h.admin("POST", `/approvals/${q.approvalId}/decide`, { decision: "APPROVE", modifiedQuery: { priority: { nested: true } } })).status, 400);

    const shownQuery = JSON.parse(row.query_json);
    const ok = await h.admin("POST", `/approvals/${q.approvalId}/decide`, {
      decision: "APPROVE",
      modifiedBody: { ...shown, amount: 50 },
      modifiedQuery: { ...shownQuery, priority: "high" },
    });
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    assert.equal(ok.data.edited, true);
    assert.ok(ok.data.changes.some((c: string) => c.includes("body.amount")));

    const hit = up.hits[up.hits.length - 1];
    assert.equal((hit.body as any).amount, 50, "the edited amount was executed");
    assert.equal((hit.body as any).email, "jane@example.com", "the unedited field kept its real (unredacted) value");
    assert.equal(Number(hit.headers["content-length"]), Buffer.byteLength(hit.raw), "Content-Length matches the edited body");
    assert.equal(hit.headers["content-type"], "application/json");
    const url = new URL(`http://x${hit.url}`);
    assert.equal(url.pathname, "/api/refund");
    assert.equal(url.searchParams.get("priority"), "high");
    assert.equal(url.searchParams.get("token"), "SECRETQUERY", "the redacted query value kept its real value");

    const audit = await sqliteGet<{ original_payload: string; modified_payload: string; amount: number; detail: string }>(
      h.dbPath,
      "SELECT original_payload, modified_payload, amount, detail FROM agent_logs WHERE status = 'APPROVED' AND action_id = ?",
      [q.approvalId]
    );
    assert.ok(audit);
    assert.equal(JSON.parse(audit!.original_payload).body.amount, 250);
    assert.equal(JSON.parse(audit!.modified_payload).body.amount, 50);
    assert.ok(!audit!.original_payload.includes("jane@") && !audit!.modified_payload.includes("jane@"), "both payloads are redacted");
    assert.ok(!audit!.modified_payload.includes("SECRETQUERY"));
    assert.equal(audit!.amount, 50, "money executed is the edited amount");
    assert.match(audit!.detail, /edited by approver/);
    const pa = await sqliteGet<{ modified_body: string; patch_encrypted: string | null }>(h.dbPath, "SELECT modified_body, patch_encrypted FROM pending_actions WHERE id = ?", [q.approvalId]);
    assert.equal(JSON.parse(pa!.modified_body).amount, 50);
    assert.equal(pa!.patch_encrypted, null);
  });

  test("MCP: edited tool arguments are what the MCP server receives", async () => {
    const received: any[] = [];
    const up = express();
    up.use(express.json());
    up.post("/mcp", (req: Request, res: Response) => {
      const m = req.body;
      if (m.method === "tools/call") {
        received.push(m.params.arguments);
        return void res.json({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `refunded ${m.params.arguments.amount}` }] } });
      }
      res.json({ jsonrpc: "2.0", id: m.id, result: {} });
    });
    const upServer = http.createServer(up);
    const upPort = await listen(upServer);
    onCleanup(() => closeServer(upServer));
    const h = await makeHarness({
      rules: { "MCP /api/mcp/tools/refund_order": { mode: "REQUIRE_APPROVAL", description: "" } },
      mount: (app, gw) => app.use("/mcp", createMcpHttpProxy(gw, { upstreamUrl: `http://127.0.0.1:${upPort}/mcp`, approvalWaitMs: 10_000 })),
    });
    const pending = postJson(`${h.base}/mcp`, { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "refund_order", arguments: { orderId: "#9", amount: 900, email: "bob@example.com" } } });
    const row = await waitFor(async () => ((await h.admin("GET", "/approvals")).data as any[]).find((a) => a.kind === "mcp" && a.status === "PENDING"), 5000, "held tool call");
    const shown = JSON.parse(row.body);
    const decided = await h.admin("POST", `/approvals/${row.id}/decide`, { decision: "APPROVE", modifiedBody: { ...shown, amount: 90 } });
    assert.equal(decided.status, 200, JSON.stringify(decided.data));
    const res = (await (await pending).json()) as any;
    assert.equal(res.result.content[0].text, "refunded 90");
    assert.deepEqual(received, [{ orderId: "#9", amount: 90, email: "bob@example.com" }]);
  });
});

// ===========================================================================
// 4. Hash-chained audit ledger
// ===========================================================================
describe("4. Tamper-evident audit ledger", () => {
  test("verify proves integrity; an edited, deleted or truncated row is detected", async () => {
    const h = await makeHarness({
      rules: { "POST /api/refund": { mode: "ALLOW", description: "", policies: [{ when: [{ field: "body.amount", op: ">", value: 100 }], mode: "BLOCK" }] } },
    });
    for (const amount of [10, 20, 500, 30, 40, 600]) await call(h.base, "POST", "/api/refund", { amount });
    await call(h.base, "GET", "/api/unlisted");
    let v = (await h.admin("GET", "/audit/verify")).data;
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(v.checked, 7);
    assert.equal(v.unsealed, 0);
    assert.match(v.headHash, /^[0-9a-f]{64}$/);
    const rows = await sqliteAll<{ id: number; amount: number | null; status: string }>(h.dbPath, "SELECT id, amount, status FROM agent_logs ORDER BY id");

    // 1) Edit a value (e.g. hide that 500 was blocked).
    const target = rows.find((r) => r.amount === 500)!;
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET status = 'ALLOWED' WHERE id = ?", [target.id]);
    v = (await h.admin("GET", "/audit/verify")).data;
    assert.equal(v.ok, false);
    assert.equal(v.brokenAt, target.id);
    assert.match(v.reason, /modified/);
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET status = ? WHERE id = ?", [target.status, target.id]);
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true, "restoring the exact value restores the chain");

    // 2) Delete a row in the middle.
    await sqliteRun(h.dbPath, "DELETE FROM agent_logs WHERE id = ?", [rows[2].id]);
    v = (await h.admin("GET", "/audit/verify")).data;
    assert.equal(v.ok, false);
    assert.equal(v.brokenAt, rows[3].id);
    assert.match(v.reason, /deleted or replaced/);
  });

  test("deleting the newest rows is detected through the recorded head", async () => {
    const h = await makeHarness({ rules: { "GET /api/x": { mode: "ALLOW", description: "" } } });
    for (let i = 0; i < 4; i++) await call(h.base, "GET", "/api/x");
    assert.equal((await h.admin("GET", "/audit/verify")).data.ok, true);
    await sqliteRun(h.dbPath, "DELETE FROM agent_logs WHERE id = (SELECT MAX(id) FROM agent_logs)");
    const v = (await h.admin("GET", "/audit/verify")).data;
    assert.equal(v.ok, false);
    assert.match(v.reason, /deleted from the end/);
  });

  test("retention pruning keeps the chain verifiable; several processes seal concurrently with identical hashes", async () => {
    const dir = tempDir();
    onCleanup(async () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const dbPath = path.join(dir, "logs.db");
    const a = createDatabase(dbPath);
    await a.init();
    const b = createDatabase(dbPath);
    await b.init();
    const ledgerA = createAuditLedger(a);
    const ledgerB = createAuditLedger(b);
    const insert = (db: typeof a, i: number) =>
      db.run("INSERT INTO agent_logs (timestamp, method, path, status, amount, workspace_id) VALUES (?, 'POST', '/api/x', 'ALLOWED', ?, 1)", [new Date(Date.now() + i).toISOString(), i]);
    for (let i = 0; i < 60; i++) await insert(i % 2 ? a : b, i);
    // Two "processes" seal at the same time.
    await Promise.all([ledgerA.sealPending(), ledgerB.sealPending(), ledgerA.sealPending()]);
    let v = await ledgerA.verify();
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(v.checked, 60);

    // The hash is exactly SHA-256(prev || canonical row): recompute the first one independently.
    const first = (await a.all<any>("SELECT * FROM agent_logs ORDER BY id LIMIT 1"))[0];
    assert.equal(first.prev_hash, GENESIS_HASH);
    assert.equal(computeRowHash(GENESIS_HASH, first), first.row_hash);

    // Retention: keep the newest 20 (a checkpoint records where the chain now starts).
    assert.equal(await ledgerA.prune(20), 40);
    v = await ledgerB.verify();
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(v.checked, 20);
    assert.ok(v.checkpoint && v.checkpoint.id > 0);
    // Removing old rows OUTSIDE the retention process is caught.
    await a.run("DELETE FROM agent_logs WHERE id = (SELECT MIN(id) FROM agent_logs)");
    v = await ledgerA.verify();
    assert.equal(v.ok, false);
    ledgerA.stop();
    ledgerB.stop();
    await a.close();
    await b.close();
  });
});

// ===========================================================================
// 5. Shadow mode + Policy Time-Machine
// ===========================================================================
describe("5. Shadow mode and replay against history", () => {
  test("SHADOW_BLOCK lets traffic through but records what it would have done; replay reports the diff", async () => {
    const shadowRules: Rules = {
      "POST /api/refund": {
        mode: "ALLOW",
        description: "",
        policies: [{ name: "big", when: [{ field: "body.amount", op: ">", value: 100 }], mode: "SHADOW_BLOCK" }],
      },
      "GET /api/orders": { mode: "SHADOW_APPROVAL", description: "" },
    };
    const h = await makeHarness({ rules: {} });
    const saved = await h.admin("POST", "/rules", shadowRules);
    assert.equal(saved.status, 200);
    assert.ok(saved.data.warnings.some((w: string) => /SHADOW/.test(w)));

    for (const amount of [50, 150, 300]) assert.equal((await call(h.base, "POST", "/api/refund", { amount, orderId: `o${amount}` })).status, 200);
    assert.equal((await call(h.base, "GET", "/api/orders")).status, 200);
    assert.equal(h.hits.length, 4, "shadow rules never stop traffic");
    const shadowRows = await sqliteAll<{ shadow: string; detail: string }>(h.dbPath, "SELECT shadow, detail FROM agent_logs WHERE shadow IS NOT NULL ORDER BY id");
    assert.deepEqual(shadowRows.map((r) => r.shadow), ["BLOCK", "BLOCK", "APPROVAL"]);
    assert.match(shadowRows[0].detail, /would have blocked \(tier:big\)/);
    const summary = (await h.admin("GET", "/protection/summary")).data;
    assert.deepEqual(summary.shadow, { wouldBlock: 2, wouldHold: 1 });

    // Replay with the CURRENT rules: nothing changes, shadow verdicts are counted.
    const same = (await h.admin("POST", "/simulate/history", { limit: 100 })).data;
    assert.equal(same.evaluated, 4);
    assert.equal(same.changed, 0);
    assert.deepEqual(same.shadow, { wouldBlock: 2, wouldHold: 1 });

    // Replay with a candidate that ENFORCES the tier, holds orders, and caps refunds per minute.
    const candidate: Rules = {
      "POST /api/refund": { mode: "ALLOW", description: "", rateLimit: 2, policies: [{ name: "big", when: [{ field: "body.amount", op: ">", value: 100 }], mode: "BLOCK" }] },
      "GET /api/orders": { mode: "REQUIRE_APPROVAL", description: "" },
    };
    const diff = (await h.admin("POST", "/simulate/history", { limit: 100, rules: candidate })).data;
    assert.equal(diff.usedCandidateRules, true);
    assert.equal(diff.evaluated, 4);
    // 50 -> ALLOW, 150 -> BLOCK, 300 -> 3rd refund in the minute -> RATE_LIMITED, orders -> held.
    assert.equal(diff.wouldBlock, 1);
    assert.equal(diff.wouldRateLimit, 1);
    assert.equal(diff.wouldHold, 1);
    assert.equal(diff.changed, 3);
    assert.equal(diff.moneyNewlyBlocked, 150);
    assert.deepEqual(
      diff.rows.map((r: any) => `${r.path}:${r.historical}>${r.simulated}`).sort(),
      ["/api/orders:ALLOW>REQUIRE_APPROVAL", "/api/refund:ALLOW>BLOCK", "/api/refund:ALLOW>RATE_LIMITED"]
    );
    // A candidate with a budget and duplicate protection.
    const guarded = (
      await h.admin("POST", "/simulate/history", {
        rules: {
          "POST /api/refund": {
            mode: "ALLOW",
            description: "",
            budget: { field: "body.amount", max: 200, windowMinutes: 60, per: "global", onExceed: "REQUIRE_APPROVAL" },
          },
          "GET /api/orders": true,
        },
      })
    ).data;
    // 50 (50) + 150 (200) fit, 300 does not.
    assert.equal(guarded.wouldHold, 1);
    assert.equal(guarded.rows[0].reason, "budget");
    // Validation.
    assert.equal((await h.admin("POST", "/simulate/history", { rules: { "POST /api/x": { mode: "MAYBE" } } })).status, 400);
    assert.equal((await h.admin("POST", "/simulate/history", { limit: 0 })).status, 400);
  });
});

// ===========================================================================
// 6. Response guard + legacy MCP SSE
// ===========================================================================
describe("6. Outbound response guard and legacy MCP HTTP+SSE", () => {
  test("unit: bulk arrays, secrets, cards, pagination cursors, text bodies", () => {
    const s = { enabled: true, maxArrayItems: 3, onLargeArray: "block" as const, onSecret: "scrub" as const };
    const big = inspectResponseBody("application/json", Buffer.from(JSON.stringify({ customers: [1, 2, 3, 4] })), s);
    assert.equal(big.action, "block");
    const secret = inspectResponseBody(
      "application/json; charset=utf-8",
      Buffer.from(JSON.stringify({ next_page_token: "abcdefghijklmnop", key: { api_key: "zzzzzzzzzzzz" }, note: "use sk_live_abcdefghijklmnop", n: 4242424242424242 })),
      s
    );
    assert.equal(secret.action, "modified");
    if (secret.action === "modified") {
      const out = JSON.parse(secret.body.toString());
      assert.equal(out.next_page_token, "abcdefghijklmnop", "pagination cursors are not credentials");
      assert.equal(out.key.api_key, "[REDACTED]");
      assert.match(out.note, /\[REDACTED:secret\]/);
      assert.equal(out.n, "[REDACTED]");
    }
    assert.equal(inspectResponseBody("text/plain", Buffer.from("token: ghp_abcdefghijklmnopqrstuvwxyz0123"), s).action, "modified");
    assert.equal(inspectResponseBody("image/png", Buffer.from([1, 2, 3]), s).action, "pass");
    assert.equal(inspectResponseBody("application/json", Buffer.from("[1,2,3,4,5]"), { ...s, enabled: false }).action, "pass");
  });

  test("HTTP: bulk dumps -> 502 Response Policy Violation, secrets scrubbed in-flight (middleware and proxy mode), audited", async () => {
    // Proxy mode: a workspace whose upstream dumps 12 rows.
    const up = await fakeUpstream();
    up.respond((_req, res) => void res.json({ rows: Array.from({ length: 12 }, (_, i) => ({ id: i })) }));
    const h = await makeHarness({ rules: { "GET /api/me": { mode: "ALLOW", description: "" } } });
    await h.admin("POST", "/workspaces", { name: "Proxy", slug: "proxy", upstreamUrl: up.base, requireKey: false });
    await h.admin("POST", "/rules", { "GET /api/customers": true }, { "x-mont-workspace": "proxy" });

    // Guard off (default): everything passes.
    let r = await call(h.base, "GET", "/api/w/proxy/customers");
    assert.equal(r.status, 200);
    assert.equal(((await r.json()) as any).rows.length, 12);

    const setup = await h.admin("POST", "/setup", { responseGuard: { enabled: true, maxArrayItems: 10, onLargeArray: "block", onSecret: "scrub" } });
    assert.equal(setup.status, 200);
    assert.ok(setup.data.warnings.some((w: string) => /withheld/.test(w)));

    // Proxy mode: 12 rows > 10 -> withheld.
    r = await call(h.base, "GET", "/api/w/proxy/customers");
    assert.equal(r.status, 502);
    const body = (await r.json()) as any;
    assert.equal(body.error, "Response Policy Violation");
    assert.equal(body.violations[0].kind, "large_array");
    assert.equal(r.headers.get("x-mont-response-guard"), "blocked");

    // A clean response is untouched (no guard header).
    r = await call(h.base, "GET", "/api/me");
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-mont-response-guard"), null);

    // Middleware mode (the host app behind the gateway answers): buffered, scrubbed, Content-Length recomputed.
    const mw = await makeHarness({
      rules: { "GET /api/leak": { mode: "ALLOW", description: "" }, "GET /api/dump": { mode: "ALLOW", description: "" } },
      mount: (app, gw) => {
        app.use("/api", gw.agentGateway);
        app.get("/api/leak", (_req: Request, res: Response) => void res.json({ user: "x", stripe_secret: "sk_live_abcdefghijklmnopqrstuvwx", card: "4242 4242 4242 4242" }));
        app.get("/api/dump", (_req: Request, res: Response) => void res.json({ items: Array.from({ length: 50 }, (_, i) => i) }));
      },
    });
    await mw.admin("POST", "/setup", { responseGuard: { enabled: true, maxArrayItems: 5, onLargeArray: "truncate", onSecret: "scrub" } });
    r = await call(mw.base, "GET", "/api/leak");
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-mont-response-guard"), "scrubbed");
    const text = await r.text();
    assert.equal(Number(r.headers.get("content-length")), Buffer.byteLength(text));
    assert.ok(!text.includes("sk_live_") && !text.includes("4242 4242"), text);
    r = await call(mw.base, "GET", "/api/dump");
    assert.equal(((await r.json()) as any).items.length, 5, "truncate mode");
    const audited = await waitFor(async () => {
      const rows = await sqliteAll<{ status: string }>(mw.dbPath, "SELECT status FROM agent_logs WHERE status LIKE 'RESPONSE_%' ORDER BY id");
      return rows.length === 2 ? rows : null;
    }, 5000, "response audit rows");
    assert.deepEqual(audited.map((a) => a.status), ["RESPONSE_SCRUBBED", "RESPONSE_SCRUBBED"]);
    const blockedAudit = await sqliteAll<{ status: string; detail: string }>(h.dbPath, "SELECT status, detail FROM agent_logs WHERE status = 'RESPONSE_BLOCKED'");
    assert.equal(blockedAudit.length, 1);
    assert.match(blockedAudit[0].detail, /12 items/);
  });

  test("MCP: oversized tool results are withheld; legacy HTTP+SSE clients work end to end", async () => {
    const calls: string[] = [];
    let session = 0;
    const up = express();
    up.use(express.json());
    up.post("/mcp", (req: Request, res: Response) => {
      const m = req.body;
      if (m.method === "initialize") {
        res.setHeader("mcp-session-id", `up-${++session}`);
        return void res.json({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "up", version: "1" } } });
      }
      if (m.method === "notifications/initialized") return void res.status(202).end();
      if (m.method === "tools/list") return void res.json({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "search_orders" }, { name: "export_customers" }] } });
      if (m.method === "tools/call") {
        calls.push(`${m.params.name}@${req.get("mcp-session-id") ?? "none"}`);
        const rows = m.params.name === "export_customers" ? 500 : 2;
        // Answer as an SSE stream (Streamable HTTP) to exercise SSE parsing.
        res.setHeader("content-type", "text/event-stream");
        res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify(Array.from({ length: rows }, (_, i) => ({ id: i }))) }] } })}\n\n`);
        return void res.end();
      }
      res.status(202).end();
    });
    up.get("/mcp", (_req: Request, res: Response) => void res.status(405).end());
    const upServer = http.createServer(up);
    const upPort = await listen(upServer);
    onCleanup(() => closeServer(upServer));

    const h = await makeHarness({
      rules: {
        "MCP /api/mcp/tools/search_orders": { mode: "ALLOW", description: "" },
        "MCP /api/mcp/tools/export_customers": { mode: "ALLOW", description: "" },
      },
      mount: (app, gw) => app.use("/mcp", createMcpHttpProxy(gw, { upstreamUrl: `http://127.0.0.1:${upPort}/mcp` })),
    });
    await h.admin("POST", "/setup", { responseGuard: { enabled: true, maxArrayItems: 100, onLargeArray: "block", onSecret: "scrub" } });

    // ---- Legacy SSE client ----
    const ac = new AbortController();
    onCleanup(async () => ac.abort());
    const stream = await fetch(`${h.base}/mcp/sse`, { headers: { accept: "text/event-stream" }, signal: ac.signal });
    assert.equal(stream.status, 200);
    assert.match(stream.headers.get("content-type") ?? "", /text\/event-stream/);
    const events: Array<{ event: string | null; data: string }> = [];
    void (async () => {
      const decoder = new TextDecoder();
      let buf = "";
      try {
        for await (const chunk of stream.body as unknown as AsyncIterable<Uint8Array>) {
          buf += decoder.decode(chunk, { stream: true });
          let cut: number;
          while ((cut = buf.indexOf("\n\n")) !== -1) {
            events.push(...parseSse(buf.slice(0, cut + 2)));
            buf = buf.slice(cut + 2);
          }
        }
      } catch {
        // aborted at cleanup
      }
    })();
    const endpoint = await waitFor(() => events.find((e) => e.event === "endpoint"), 5000, "endpoint event");
    assert.match(endpoint.data, /^\/mcp\/messages\?sessionId=[0-9a-f-]{36}$/);
    const send = async (m: unknown) => (await postJson(`${h.base}${endpoint.data}`, m)).status;
    const reply = (id: number) => waitFor(() => events.map((e) => (e.event === "message" ? JSON.parse(e.data) : null)).find((m) => m && m.id === id), 8000, `reply ${id}`);

    assert.equal(await send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "old-client", version: "0.1" } } }), 202);
    assert.equal((await reply(1)).result.serverInfo.name, "up");
    assert.equal(await send({ jsonrpc: "2.0", method: "notifications/initialized" }), 202);
    await send({ jsonrpc: "2.0", id: 3, method: "tools/list" });
    assert.equal((await reply(3)).result.tools.length, 2);
    await send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "search_orders", arguments: { q: "late" } } });
    const ok = await reply(4);
    assert.equal(JSON.parse(ok.result.content[0].text).length, 2);
    // Upstream session id from initialize is reused for later calls.
    assert.deepEqual(calls, ["search_orders@up-1"]);
    // Blocked (unlisted) tool -> refusal on the stream, never reaches the server.
    await send({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "drop_tables", arguments: {} } });
    assert.equal((await reply(5)).result._meta["mont/decision"], "BLOCK");
    // Oversized result -> withheld by the response guard.
    await send({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "export_customers", arguments: {} } });
    const withheld = await reply(6);
    assert.equal(withheld.result.isError, true);
    assert.equal(withheld.result._meta["mont/decision"], "RESPONSE_BLOCKED");
    assert.match(withheld.result.content[0].text, /Response Policy Violation/);
    assert.equal(calls.length, 2, "the call ran; only its result was withheld");
    // Unknown session.
    assert.equal((await postJson(`${h.base}/mcp/messages?sessionId=nope`, { jsonrpc: "2.0", id: 9, method: "ping" })).status, 404);

    // ---- Streamable HTTP client gets the same guard ----
    const direct = (await (await postJson(`${h.base}/mcp`, { jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "export_customers", arguments: {} } }, { accept: "application/json, text/event-stream" })).text());
    assert.match(direct, /RESPONSE_BLOCKED/);
    await waitFor(async () => (await sqliteAll<{ status: string }>(h.dbPath, "SELECT status FROM agent_logs WHERE status = 'RESPONSE_BLOCKED'")).length === 2, 5000, "2 RESPONSE_BLOCKED rows");
    ac.abort();
    await sleep(50);
  });

  test("helpers: workspace path parsing", () => {
    assert.deepEqual(splitWorkspacePath("/api/w/acme/refund?x=1"), { slug: "acme", rest: "/api/refund?x=1" });
    assert.deepEqual(splitWorkspacePath("/api/w/acme"), { slug: "acme", rest: "/api" });
    assert.equal(splitWorkspacePath("/api/refund"), null);
    assert.equal(splitWorkspacePath("/api/w/Bad_Slug!/x"), null);
    assert.ok(ADMIN_TOKEN.length > 10);
  });
});
