/**
 * v1.2 suite: PII/secret scrubber, starter policy packs + wildcard rules, zero-tunnel phone
 * approvals (Telegram long-polling, Slack Socket Mode), and the MCP tool-call proxy (HTTP + stdio).
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import http from "http";
import os from "os";
import path from "path";
import { PassThrough } from "stream";
import readline from "readline";
import express from "express";
import type { Request, Response } from "express";
import { createMcpHttpProxy, startMcpStdioProxy } from "../src/gateway";
import type { Rules } from "../src/gateway";
import { createRedactor, luhnValid } from "../src/core/redactor";
import { matcherFor } from "../src/core/rules";
import { signButtonToken } from "../src/core/approvalSigning";
import {
  ADMIN_TOKEN,
  fakeTelegram,
  attachWebSocketServer,
  closeServer,
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
import type { WsConnection } from "./helpers";

after(runCleanups);

// Values that must never appear in SQLite or in anything sent to a third party.
const SECRETS = {
  bearer: "Bearer sk_live_51HxQ9vLkmN0pQrStUvWxYz123456",
  apiKey: "ak_9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  cookie: "session=s3cr3tc00ki3value",
  password: "hunter2-correct-horse",
  card: "4111 1111 1111 1111",
  cardDigits: "4111111111111111",
  email: "jane.customer@example.com",
  emailInUrl: "jane.customer%40example.com",
  phone: "+1 415 555 0172",
  stripeKey: "sk_live_abcdefghijklmnop1234",
};

function assertNoSecrets(haystack: string, where: string): void {
  for (const [name, value] of Object.entries(SECRETS)) {
    assert.ok(!haystack.includes(value), `${where} leaked ${name}: ${value}`);
  }
}

// ---------------------------------------------------------------------------
// 1. Redactor
// ---------------------------------------------------------------------------
describe("1. deterministic PII & secret scrubber", () => {
  const on = createRedactor(() => ({ redactEmails: true, redactPhones: true }));
  const off = createRedactor(() => ({ redactEmails: false, redactPhones: false }));

  test("cards: Luhn + network prefix; timestamps and random numbers survive", () => {
    assert.equal(luhnValid("4111111111111111"), true);
    assert.equal(luhnValid("4111111111111112"), false);
    assert.equal(on.text(`pay with ${SECRETS.card} today`), "pay with [REDACTED:card] today");
    assert.equal(on.text("card 4111-1111-1111-1111"), "card [REDACTED:card]");
    assert.equal(on.text("order 4111111111111112"), "order 4111111111111112", "Luhn-invalid numbers are not cards");
    assert.equal(on.text("ts 1730900000000"), "ts 1730900000000", "ms timestamps (prefix 1) are never cards");
    assert.deepEqual(on.json({ pan: 4111111111111111, createdAt: 1730900000000, qty: 3 }), { pan: "[REDACTED]", createdAt: 1730900000000, qty: 3 });
    assert.deepEqual(on.json({ n: 4111111111111111 }), { n: "[REDACTED:card]" });
  });

  test("secret keys and credential formats are always redacted", () => {
    const out = on.json({
      password: "x",
      client_secret: "y",
      apiKey: "z",
      nested: { accessToken: "t", list: [{ "X-Api-Key": "k" }], cvv: 123 },
      note: `use ${SECRETS.stripeKey} and ${SECRETS.bearer}`,
      jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      gh: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      tg: "123456789:AAH_abcdefghijklmnopqrstuvwxyz012345",
      amount: 250,
    }) as Record<string, any>;
    assert.equal(out.password, "[REDACTED]");
    assert.equal(out.client_secret, "[REDACTED]");
    assert.equal(out.apiKey, "[REDACTED]");
    assert.equal(out.nested.accessToken, "[REDACTED]");
    assert.equal(out.nested.list[0]["X-Api-Key"], "[REDACTED]");
    assert.equal(out.nested.cvv, "[REDACTED]");
    assert.equal(out.note, "use [REDACTED:secret] and [REDACTED:secret]");
    assert.equal(out.jwt, "[REDACTED:secret]");
    assert.equal(out.gh, "[REDACTED:secret]");
    assert.equal(out.tg, "[REDACTED:secret]");
    assert.equal(out.amount, 250, "business fields are untouched");
    assert.equal(off.json({ password: "x" }) && (off.json({ password: "x" }) as any).password, "[REDACTED]", "secrets ignore the PII toggles");

    const h = on.headers({ authorization: SECRETS.bearer, cookie: SECRETS.cookie, "x-api-key": SECRETS.apiKey, "user-agent": "bot/1", "content-length": "10" });
    assert.deepEqual(h, { authorization: "[REDACTED]", cookie: "[REDACTED]", "x-api-key": "[REDACTED]", "user-agent": "bot/1" });
  });

  test("emails and phones: masked by default, configurable", () => {
    const body = { email: SECRETS.email, contact: { phone: SECRETS.phone }, mailingAddress: "1 Main St", note: `call ${SECRETS.phone} or mail ${SECRETS.email}` };
    const masked = on.json(body) as any;
    assert.equal(masked.email, "j***@example.com");
    assert.equal(masked.contact.phone, "[REDACTED:phone ••72]");
    assert.equal(masked.mailingAddress, "1 Main St", "addresses are not emails");
    assert.equal(masked.note, "call [REDACTED:phone ••72] or mail j***@example.com");
    assert.deepEqual(off.json(body), body);
  });

  test("HTTP: nothing sensitive reaches SQLite, logs or notifications, yet policies and replay see real data", async () => {
    // A fake webhook receiver captures exactly what the gateway sends to third parties.
    const captured: string[] = [];
    const receiver = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        captured.push(data);
        res.end("ok");
      });
    });
    const rPort = await listen(receiver);
    onCleanup(() => closeServer(receiver));

    const h = await makeHarness({
      rules: {
        "POST /api/customers/update": {
          mode: "REQUIRE_APPROVAL",
          description: "",
          policies: [{ name: "vip", when: [{ field: "body.email", op: "===", value: "vip@shop.test" }], mode: "ALLOW" }],
        },
      },
    });
    const setup = await h.admin("POST", "/setup", { notifications: { webhook: { enabled: true, url: `http://127.0.0.1:${rPort}/hook` } } });
    assert.equal(setup.status, 200);

    // Policy matches on the real (unredacted) email.
    const vip = await postJson(`${h.base}/api/customers/update`, { email: "vip@shop.test" });
    assert.equal(vip.status, 200);

    const res = await postJson(
      `${h.base}/api/customers/update?api_key=${encodeURIComponent(SECRETS.apiKey)}&ref=${encodeURIComponent(SECRETS.email)}`,
      {
        email: SECRETS.email,
        phone: SECRETS.phone,
        password: SECRETS.password,
        card: SECRETS.card,
        memo: `customer paid with ${SECRETS.card}`,
        note: `token ${SECRETS.stripeKey}`,
      },
      { authorization: SECRETS.bearer, cookie: SECRETS.cookie, "x-api-key": SECRETS.apiKey, "x-agent-reason": `customer ${SECRETS.email} asked` }
    );
    assert.equal(res.status, 202);
    const { approvalId } = (await res.json()) as { approvalId: number };

    await waitFor(() => captured.length > 0, 5000, "webhook notification");
    const rows = await sqliteAll<Record<string, unknown>>(h.dbPath, "SELECT * FROM pending_actions WHERE id = ?", [approvalId]);
    const { encrypted_payload, ...visible } = rows[0];
    assert.ok(typeof encrypted_payload === "string" && encrypted_payload.length > 0);
    assertNoSecrets(JSON.stringify(visible), "pending_actions");
    const storedBody = JSON.parse(String(visible.body));
    assert.equal(storedBody.email, "j***@example.com");
    assert.equal(storedBody.card, "[REDACTED]", "a key named card is masked outright");
    assert.equal(storedBody.memo, "customer paid with [REDACTED:card]", "card numbers inside free text are found by Luhn");
    assert.match(String(visible.path), /j\*\*\*%40example\.com/, "URL-encoded emails in the query string are masked too");
    assertNoSecrets(JSON.stringify(await sqliteAll(h.dbPath, "SELECT * FROM agent_logs")), "agent_logs");
    assertNoSecrets(captured.join("\n"), "webhook notification");

    // Approved replay uses the encrypted original: the app receives the real values.
    const decided = await h.admin("POST", `/approvals/${approvalId}/decide`, { decision: "APPROVE" });
    assert.equal(decided.status, 200);
    const replayed = h.hits[h.hits.length - 1];
    assert.deepEqual((replayed.body as any).password, SECRETS.password);
    assert.deepEqual((replayed.body as any).card, SECRETS.card);
    assertNoSecrets(JSON.stringify(await sqliteAll(h.dbPath, "SELECT response_preview, body, headers FROM pending_actions")), "pending_actions after approval");

    // Toggle off: emails are stored as-is (cards and secrets still are not).
    await h.admin("POST", "/setup", { privacy: { redactEmails: false } });
    const r2 = await postJson(`${h.base}/api/customers/update`, { email: SECRETS.email, card: SECRETS.card });
    const id2 = ((await r2.json()) as { approvalId: number }).approvalId;
    const row2 = await sqliteGet<{ body: string }>(h.dbPath, "SELECT body FROM pending_actions WHERE id = ?", [id2]);
    assert.ok(row2!.body.includes(SECRETS.email));
    assert.ok(!row2!.body.includes(SECRETS.card));
  });
});

// ---------------------------------------------------------------------------
// 2. Wildcard rules + starter policy packs
// ---------------------------------------------------------------------------
describe("2. wildcard rules and 1-click policy packs", () => {
  test("precedence: exact > method wildcard > any-method wildcard; most specific wins; MCP isolated", () => {
    const rules: Rules = {
      "/api/*": { mode: "ALLOW", description: "" },
      "DELETE /api/*": { mode: "BLOCK", description: "" },
      "POST /api/*refund*": { mode: "REQUIRE_APPROVAL", description: "" },
      "POST /api/v2/*refund*": { mode: "BLOCK", description: "" },
      "POST /api/refund": { mode: "ALLOW", description: "" },
      "MCP /api/mcp/tools/*delete*": { mode: "BLOCK", description: "" },
    };
    const m = matcherFor(rules);
    assert.equal(m("POST", "/api/refund")?.key, "POST /api/refund");
    assert.equal(m("POST", "/api/shop/refunds")?.key, "POST /api/*refund*");
    assert.equal(m("POST", "/api/v2/orders/9/refund")?.key, "POST /api/v2/*refund*");
    assert.equal(m("DELETE", "/api/anything")?.key, "DELETE /api/*");
    assert.equal(m("GET", "/api/anything")?.key, "/api/*");
    assert.equal(m("MCP", "/api/mcp/tools/delete_user")?.key, "MCP /api/mcp/tools/*delete*");
    assert.equal(m("MCP", "/api/mcp/tools/search"), undefined, "any-method HTTP rules never govern MCP tools");
    assert.equal(m("GET", "/apix/thing"), undefined);
  });

  test("E-Commerce pack: reads allowed, refunds/discounts tiered, deletes blocked", async () => {
    const h = await makeHarness({ rules: { "GET /api/health": { mode: "ALLOW", description: "" } } });
    const list = await h.admin("GET", "/setup/presets");
    assert.deepEqual(list.data.map((p: { id: string }) => p.id), ["ecommerce", "fintech", "crud"]);
    const applied = await h.admin("POST", "/setup/presets/ecommerce/apply", { mode: "merge" });
    assert.equal(applied.status, 200);
    assert.ok(applied.data.rules["GET /api/health"], "merge keeps existing rules");

    const call = (method: string, p: string, body?: unknown) =>
      fetch(`${h.base}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.status);
    assert.equal(await call("GET", "/api/v2/orders/123"), 200);
    assert.equal(await call("POST", "/api/shop/refund", { amount: 20 }), 200);
    assert.equal(await call("POST", "/api/shop/refund", { amount: 80 }), 202);
    assert.equal(await call("POST", "/api/refunds", { orderId: 1 }), 202, "missing amount falls back to approval");
    assert.equal(await call("POST", "/api/discounts", { percentage: 10 }), 200);
    assert.equal(await call("POST", "/api/discounts", { percentage: 30, amount: 10 }), 202, "either condition triggers approval");
    assert.equal(await call("DELETE", "/api/customers/5"), 403);
    assert.equal(await call("DELETE", "/api/store/products"), 403);
    assert.equal(await call("POST", "/api/unrelated"), 403, "everything else stays default-deny");

    assert.equal((await h.admin("POST", "/setup/presets/nope/apply", {})).status, 404);
  });

  test("FinTech pack: transfers/payouts > $100 need approval, charges capped at 5/min, account deletion blocked", async () => {
    const h = await makeHarness({});
    assert.equal((await h.admin("POST", "/setup/presets/fintech/apply", { mode: "replace" })).status, 200);
    const s = (method: string, p: string, body?: unknown) =>
      fetch(`${h.base}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.status);
    assert.equal(await s("POST", "/api/transfers", { amount: 50 }), 200);
    assert.equal(await s("POST", "/api/transfers", { amount: 150 }), 202);
    assert.equal(await s("POST", "/api/payouts", { amount: 101 }), 202);
    const charges = [];
    for (let i = 0; i < 6; i++) charges.push(await s("POST", "/api/charges", { amount: 5 }));
    assert.deepEqual(charges, [200, 200, 200, 200, 200, 429]);
    assert.equal(await s("DELETE", "/api/account"), 403);
  });

  test("CRUD pack: GET allowed, writes rate-limited, bulk needs approval, every DELETE blocked; replace drops old rules", async () => {
    const h = await makeHarness({ rules: { "DELETE /api/legacy": { mode: "ALLOW", description: "" } } });
    const res = await h.admin("POST", "/setup/presets/crud/apply", { mode: "replace" });
    assert.equal(res.status, 200);
    assert.equal(res.data.rules["DELETE /api/legacy"], undefined);
    const s = (method: string, p: string, body?: unknown) =>
      fetch(`${h.base}${p}`, { method, headers: { "content-type": "application/json" }, body: body !== undefined ? JSON.stringify(body) : undefined }).then((r) => r.status);
    assert.equal(await s("GET", "/api/users/1"), 200);
    assert.equal(await s("PUT", "/api/users/1", { name: "a" }), 200);
    assert.equal(await s("PUT", "/api/users", [{ id: 1 }, { id: 2 }]), 202, "array body = bulk");
    assert.equal(await s("POST", "/api/items", { ids: [1, 2, 3] }), 202, "ids list = bulk");
    assert.equal(await s("PATCH", "/api/orders", { items: [{}, {}] }), 202, "many items = bulk");
    assert.equal(await s("POST", "/api/bulk-import", {}), 202, "bulk routes always need approval");
    assert.equal(await s("DELETE", "/api/users/1"), 403);
    assert.equal(await s("DELETE", "/api/legacy"), 403);
  });
});

// ---------------------------------------------------------------------------
// 3. Zero-tunnel phone approvals
// ---------------------------------------------------------------------------
describe("3. zero-tunnel phone approvals", () => {
  test("Telegram long-polling: signed buttons, chat + approver checks, tamper-proof, decides without any public URL", async () => {
    const token = "123456789:AAH_test_token_abcdefghijklmnopqrstuv";
    const tg = await fakeTelegram(token);
    const h = await makeHarness({
      rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } },
      gatewayOptions: { telegramApiBase: tg.base, telegramPollTimeoutSec: 1 },
    });
    const saved = await h.admin("POST", "/setup", {
      notifications: { telegram: { enabled: true, mode: "polling", botToken: token, chatId: "-100555", approverIds: "777" } },
    });
    assert.equal(saved.status, 200);
    assert.equal(saved.data.settings.publicBaseUrl, "", "no public URL configured");
    await waitFor(async () => (await h.admin("GET", "/setup")).data.bridges.telegram.state === "connected", 8000, "telegram bridge connected");

    const queued = await postJson(`${h.base}/api/refund`, { orderId: "#1007", amount: 250, cardNumber: SECRETS.card });
    const { approvalId } = (await queued.json()) as { approvalId: number };
    const msg = await waitFor(() => tg.sent.find((m) => String(m.text).includes(`#${approvalId}`)), 5000, "telegram sendMessage");
    assertNoSecrets(JSON.stringify(msg), "telegram message");
    const [approveBtn, rejectBtn] = msg.reply_markup.inline_keyboard[0];
    assert.match(approveBtn.callback_data, /^mont:A:\d+:[A-Za-z0-9_-]{22}$/);
    assert.ok(Buffer.byteLength(approveBtn.callback_data) <= 64, "fits Telegram's 64-byte callback_data limit");
    assert.equal(approveBtn.url, undefined, "callback buttons, not links");

    const tap = (data: string, chatId: number, userId: number) =>
      tg.push({ callback_query: { id: `cq${Math.random()}`, data, from: { id: userId, username: `u${userId}` }, message: { message_id: 1, chat: { id: chatId } } } });
    const answers = () => tg.calls.filter((c) => c.method === "answerCallbackQuery").length;

    // Wrong chat, wrong user, forged MAC, button for another action: all ignored.
    tap(approveBtn.callback_data, -100999, 777);
    tap(approveBtn.callback_data, -100555, 555);
    tap(approveBtn.callback_data.slice(0, -1) + (approveBtn.callback_data.endsWith("A") ? "B" : "A"), -100555, 777);
    tap(signButtonToken("f".repeat(64), approvalId, "APPROVE", "2026-01-01T00:00:00.000Z"), -100555, 777);
    await waitFor(() => answers() >= 4, 6000, "four rejected taps answered");
    assert.equal(await pendingStatus(h.dbPath, approvalId), "PENDING");
    assert.equal(h.hits.length, 0);

    // The approver taps Approve: executed once, keyboard removed, outcome posted in the chat.
    tap(approveBtn.callback_data, -100555, 777);
    await waitFor(async () => (await pendingStatus(h.dbPath, approvalId)) === "APPROVED", 6000, "approved via Telegram");
    assert.equal(h.hits.length, 1);
    await waitFor(() => tg.calls.some((c) => c.method === "editMessageReplyMarkup"), 3000, "keyboard removed");
    await waitFor(() => tg.sent.some((m) => /Approved and executed #\d+ by telegram:@u777/.test(String(m.text))), 3000, "outcome message");
    const row = await sqliteGet<{ decided_by: string }>(h.dbPath, "SELECT decided_by FROM pending_actions WHERE id = ?", [approvalId]);
    assert.equal(row?.decided_by, "telegram:@u777");

    // Replaying the same button does nothing more.
    tap(approveBtn.callback_data, -100555, 777);
    tap(rejectBtn.callback_data, -100555, 777);
    await sleep(800);
    assert.equal(h.hits.length, 1);
  });

  test("Slack Socket Mode: outbound WebSocket, acks envelopes, approver + channel checks, decides with no public URL", async () => {
    const posted: Array<Record<string, any>> = [];
    const updated: Array<Record<string, any>> = [];
    let conn: WsConnection | null = null;
    const app = express();
    app.use(express.json());
    const server = http.createServer(app);
    const port = await listen(server);
    onCleanup(() => closeServer(server));
    app.post("/apps.connections.open", (req: Request, res: Response) => {
      assert.equal(req.get("authorization"), "Bearer xapp-1-A0123-4567-abcdef");
      res.json({ ok: true, url: `ws://127.0.0.1:${port}/socket` });
    });
    app.post("/chat.postMessage", (req: Request, res: Response) => {
      posted.push(req.body);
      res.json({ ok: true, ts: `1700000000.00${posted.length}`, channel: req.body.channel });
    });
    app.post("/chat.update", (req: Request, res: Response) => {
      updated.push(req.body);
      res.json({ ok: true });
    });
    attachWebSocketServer(server, "/socket", (c) => {
      conn = c;
      c.send(JSON.stringify({ type: "hello" }));
    });

    const h = await makeHarness({
      rules: { "POST /api/payout": { mode: "REQUIRE_APPROVAL", description: "" } },
      gatewayOptions: { slackApiBase: `http://127.0.0.1:${port}` },
    });
    const bad = await h.admin("POST", "/setup", { notifications: { slack: { botToken: "not-a-token" } } });
    assert.equal(bad.status, 400);
    const ok = await h.admin("POST", "/setup", {
      notifications: {
        slack: { enabled: true, mode: "socket", botToken: "xoxb-1234-5678-abcdefgh", appToken: "xapp-1-A0123-4567-abcdef", channelId: "C0123ABCD", approverIds: "U0777OWNER" },
      },
    });
    assert.equal(ok.status, 200);
    await waitFor(() => conn !== null, 8000, "socket mode connection");
    await waitFor(async () => (await h.admin("GET", "/setup")).data.bridges.slack.state === "connected", 5000, "slack bridge connected");

    const queued = await postJson(`${h.base}/api/payout`, { amount: 900, destination: "acct_attacker", password: SECRETS.password });
    const { approvalId } = (await queued.json()) as { approvalId: number };
    const msg = await waitFor(() => posted.find((m) => String(m.text).includes(`#${approvalId}`)), 5000, "chat.postMessage");
    assertNoSecrets(JSON.stringify(msg), "slack message");
    const buttons = msg.blocks.find((b: { type: string }) => b.type === "actions").elements;
    const reject = buttons.find((b: { action_id: string }) => b.action_id === "mont_reject");

    const envelope = (id: string, userId: string, channelId: string) =>
      conn!.send(
        JSON.stringify({
          envelope_id: id,
          type: "interactive",
          payload: {
            type: "block_actions",
            user: { id: userId, username: "owner" },
            channel: { id: channelId },
            message: { ts: msg.ts ?? "1700000000.001" },
            actions: [{ action_id: "mont_reject", value: reject.value }],
          },
        })
      );

    envelope("env-1", "U0999STRANGER", "C0123ABCD");
    envelope("env-2", "U0777OWNER", "C0999OTHER");
    await waitFor(() => conn!.received.length >= 2, 3000, "acks");
    await sleep(300);
    assert.equal(await pendingStatus(h.dbPath, approvalId), "PENDING", "non-approver / wrong channel cannot decide");

    envelope("env-3", "U0777OWNER", "C0123ABCD");
    await waitFor(async () => (await pendingStatus(h.dbPath, approvalId)) === "REJECTED", 5000, "rejected via Slack");
    assert.deepEqual(conn!.received.map((r) => JSON.parse(r).envelope_id), ["env-1", "env-2", "env-3"], "every envelope acked");
    await waitFor(() => updated.some((u) => /Rejected #\d+ by slack:owner/.test(String(u.text))), 3000, "chat.update with outcome");
    assert.equal(h.hits.length, 0);
  });
});

// ---------------------------------------------------------------------------
// 4. MCP tool-call proxy
// ---------------------------------------------------------------------------
const MCP_RULES: Rules = {
  "MCP /api/mcp/tools/search_orders": { mode: "ALLOW", description: "" },
  "MCP /api/mcp/tools/refund_order": {
    mode: "REQUIRE_APPROVAL",
    description: "",
    policies: [
      { name: "small", when: [{ field: "body.amount", op: "<=", value: 100 }], mode: "ALLOW" },
      { name: "huge", when: [{ field: "body.amount", op: ">", value: 1000 }], mode: "BLOCK" },
    ],
  },
  "MCP /api/mcp/tools/*delete*": { mode: "BLOCK", description: "" },
  "MCP /api/mcp/tools/send_email": { mode: "ALLOW", description: "", rateLimit: 2 },
  // HTTP rules that must NOT leak into MCP tool decisions:
  "POST /api/*": { mode: "ALLOW", description: "" },
  "/api/*": { mode: "ALLOW", description: "" },
};

describe("4. MCP tool-call proxy", () => {
  test("Streamable HTTP: passthrough, rules, payload policies, rate limit, approve / reject / timeout / disconnect", async () => {
    const upstreamCalls: Array<{ name: string; arguments: unknown }> = [];
    const up = express();
    up.use(express.json());
    up.post("/mcp", (req: Request, res: Response) => {
      const m = req.body;
      res.setHeader("mcp-session-id", "sess-1");
      if (m.method === "initialize") return void res.json({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "up", version: "1" } } });
      if (m.method === "tools/list") return void res.json({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "search_orders" }] } });
      if (m.method === "tools/call") {
        upstreamCalls.push(m.params);
        return void res.json({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `ran ${m.params.name}` }] } });
      }
      res.status(202).end();
    });
    const upServer = http.createServer(up);
    const upPort = await listen(upServer);
    onCleanup(() => closeServer(upServer));

    const h = await makeHarness({
      rules: MCP_RULES,
      mount: (app, gw) => {
        app.use("/mcp", createMcpHttpProxy(gw, { upstreamUrl: `http://127.0.0.1:${upPort}/mcp` }));
        app.use("/mcp-short", createMcpHttpProxy(gw, { upstreamUrl: `http://127.0.0.1:${upPort}/mcp`, approvalWaitMs: 600 }));
      },
    });
    let nextId = 1;
    const rpc = async (method: string, params?: unknown, route = "/mcp", signal?: AbortSignal) => {
      const res = await postJson(`${h.base}${route}`, { jsonrpc: "2.0", id: nextId++, method, params }, { accept: "application/json, text/event-stream", "user-agent": "test-agent/1.0" }, signal);
      return { status: res.status, session: res.headers.get("mcp-session-id"), body: (await res.json()) as any };
    };
    const call = (name: string, args: unknown, route?: string, signal?: AbortSignal) => rpc("tools/call", { name, arguments: args }, route, signal);

    const init = await rpc("initialize", { protocolVersion: "2025-06-18", clientInfo: { name: "t", version: "1" } });
    assert.equal(init.status, 200);
    assert.equal(init.session, "sess-1", "session header passes through");
    assert.equal((await rpc("tools/list")).body.result.tools[0].name, "search_orders");

    const allowed = await call("search_orders", { q: "late" });
    assert.equal(allowed.body.result.content[0].text, "ran search_orders");

    const del = await call("delete_customer", { id: 5 });
    assert.equal(del.body.result.isError, true);
    assert.equal(del.body.result._meta["mont/decision"], "BLOCK");
    const unknown = await call("export_database", {});
    assert.equal(unknown.body.result._meta["mont/decision"], "BLOCK", "unlisted tools are default-deny even with POST /api/* and /api/* rules");
    assert.equal((await call("refund_order", { amount: 50 })).body.result.content[0].text, "ran refund_order");
    assert.equal((await call("refund_order", { amount: 5000 })).body.result._meta["mont/decision"], "BLOCK");
    assert.deepEqual(upstreamCalls.map((c) => c.name), ["search_orders", "refund_order"], "blocked calls never reached the server");

    const pendingList = async () => ((await h.admin("GET", "/approvals")).data as any[]).filter((a) => a.status === "PENDING" && a.kind === "mcp");

    // "50" as a string is not <= 100 (strict types): it is held, not auto-allowed.
    const stringy = call("refund_order", { amount: "50" });
    const rowS = await waitFor(async () => (await pendingList())[0], 5000, "held string-amount call");
    await h.admin("POST", `/approvals/${rowS.id}/decide`, { decision: "REJECT" });
    assert.equal((await stringy).body.result._meta["mont/decision"], "REJECTED");

    // Rate limit (2/min for send_email).
    const e1 = await call("send_email", { to: "a@b.c" });
    const e2 = await call("send_email", { to: "a@b.c" });
    const e3 = await call("send_email", { to: "a@b.c" });
    assert.equal(e1.body.result.isError, undefined);
    assert.equal(e2.body.result.isError, undefined);
    assert.equal(e3.body.result._meta["mont/decision"], "RATE_LIMITED");

    // Held -> approved from the dashboard -> executed, result returned to the waiting client.
    const before = upstreamCalls.length;
    const held = call("refund_order", { amount: 300, orderId: "#1007", email: SECRETS.email });
    const row = await waitFor(async () => (await pendingList())[0], 5000, "held MCP call");
    assert.equal(row.method, "MCP");
    assert.equal(row.path, "/api/mcp/tools/refund_order");
    assert.ok(!String(row.body).includes(SECRETS.email), "arguments are redacted in the approval row");
    assert.equal(JSON.parse(row.body).amount, 300);
    assert.equal(upstreamCalls.length, before, "nothing executed while held");
    const approve = await h.admin("POST", `/approvals/${row.id}/decide`, { decision: "APPROVE" });
    assert.equal(approve.status, 200);
    assert.equal(approve.data.status, "APPROVED");
    const heldResult = await held;
    assert.equal(heldResult.body.result.content[0].text, "ran refund_order");
    assert.equal(upstreamCalls.length, before + 1);
    assert.deepEqual(upstreamCalls[upstreamCalls.length - 1].arguments, { amount: 300, orderId: "#1007", email: SECRETS.email }, "the original arguments are executed");

    // Held -> rejected.
    const heldR = call("refund_order", { amount: 400 });
    const rowR = await waitFor(async () => (await pendingList())[0], 5000, "second held call");
    await h.admin("POST", `/approvals/${rowR.id}/decide`, { decision: "REJECT" });
    const rejected = await heldR;
    assert.equal(rejected.body.result._meta["mont/decision"], "REJECTED");
    assert.equal(upstreamCalls.length, before + 1);

    // Held -> nobody decides -> expired, and can never be approved afterwards.
    const timedOut = await call("refund_order", { amount: 500 }, "/mcp-short");
    assert.equal(timedOut.body.result._meta["mont/decision"], "EXPIRED");
    const expiredId = timedOut.body.result._meta["mont/approvalId"];
    assert.equal(await pendingStatus(h.dbPath, expiredId), "EXPIRED");
    assert.equal((await h.admin("POST", `/approvals/${expiredId}/decide`, { decision: "APPROVE" })).status, 410);

    // Held -> the agent disconnects -> expired immediately.
    const ac = new AbortController();
    const gone = call("refund_order", { amount: 600 }, "/mcp", ac.signal).catch(() => "aborted");
    const rowG = await waitFor(async () => (await pendingList())[0], 5000, "third held call");
    ac.abort();
    assert.equal(await gone, "aborted");
    await waitFor(async () => (await pendingStatus(h.dbPath, rowG.id)) === "EXPIRED", 5000, "expired on disconnect");
    assert.equal(upstreamCalls.length, before + 1);

    // Protocol hygiene.
    const batch = await postJson(`${h.base}/mcp`, [{ jsonrpc: "2.0", id: 99, method: "tools/call", params: { name: "search_orders" } }]);
    assert.equal(batch.status, 400);
    const garbage = await fetch(`${h.base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{oops" });
    assert.equal(garbage.status, 400);

    // Audit log rows exist for MCP decisions.
    const logs = await sqliteAll<{ method: string; status: string; path: string }>(h.dbPath, "SELECT method, status, path FROM agent_logs WHERE method = 'MCP'");
    assert.ok(logs.some((l) => l.status === "BLOCKED" && l.path.endsWith("delete_customer")));
    assert.ok(logs.some((l) => l.status === "ALLOWED" && l.path.endsWith("search_orders")));
    assert.ok(logs.some((l) => l.status === "RATE_LIMITED"));
  });

  test("stdio: spawns the server, guards tools/call, and an approval from ANOTHER gateway process releases the held call", async () => {
    const dir = tempDir();
    onCleanup(async () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const logFile = path.join(dir, "server-calls.log");
    fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(MCP_RULES));

    // Gateway A runs the stdio proxy; gateway B (same data folder) serves the admin API.
    const a = await makeHarness({ dir });
    const b = await makeHarness({ dir });
    const input = new PassThrough();
    const output = new PassThrough();
    const proxy = startMcpStdioProxy(a.gateway, {
      command: process.execPath,
      args: [path.resolve(__dirname, "fixtures", "fake-mcp-server.mjs")],
      env: { ...process.env, FAKE_MCP_LOG: logFile },
      input,
      output,
    });
    onCleanup(async () => {
      proxy.stop();
      await proxy.exited;
    });

    const responses = new Map<number | null, any>();
    readline.createInterface({ input: output }).on("line", (line) => {
      const m = JSON.parse(line);
      responses.set(m.id ?? null, m);
    });
    const send = (m: unknown) => input.write(`${typeof m === "string" ? m : JSON.stringify(m)}\n`);
    const reply = (id: number | null) => waitFor(() => responses.get(id), 8000, `stdio response ${id}`);
    const serverCalls = () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "claude-desktop", version: "9.9" } } });
    assert.equal((await reply(1)).result.serverInfo.name, "fake-mcp");

    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "search_orders", arguments: { q: "x" } } });
    assert.equal((await reply(2)).result.content[0].text, 'ran search_orders {"q":"x"}');

    send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "delete_customer", arguments: { id: 1 } } });
    assert.equal((await reply(3)).result._meta["mont/decision"], "BLOCK");

    send("not json at all");
    assert.equal((await reply(null)).error.code, -32700);

    send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "refund_order", arguments: { amount: 250 } } });
    const row = await waitFor(
      async () => (await sqliteGet<{ id: number; caller_ua: string; owner: string }>(a.dbPath, "SELECT id, caller_ua, owner FROM pending_actions WHERE kind = 'mcp' AND status = 'PENDING'")),
      5000,
      "held stdio call"
    );
    assert.equal(row.caller_ua, "claude-desktop/9.9 (mcp stdio)");
    assert.equal(responses.get(4), undefined, "the client is still waiting");

    // Approve through gateway B: a different instance with no in-memory waiter.
    const decided = await b.admin("POST", `/approvals/${row.id}/decide`, { decision: "APPROVE" });
    assert.equal(decided.status, 202);
    assert.equal(decided.data.status, "EXECUTING");
    assert.equal((await reply(4)).result.content[0].text, 'ran refund_order {"amount":250}');
    await waitFor(async () => (await pendingStatus(a.dbPath, row.id)) === "APPROVED", 5000, "outcome recorded by the owning process");

    assert.deepEqual(serverCalls().map((c: { name: string }) => c.name), ["search_orders", "refund_order"], "the blocked tool never reached the server");
  });

  test("stdio: client EOF right after an allowed call still delivers it (drain before closing the server)", async () => {
    const h = await makeHarness({ rules: MCP_RULES });
    const logFile = path.join(h.dir, "eof-calls.log");
    const input = new PassThrough();
    const output = new PassThrough();
    const lines: string[] = [];
    readline.createInterface({ input: output }).on("line", (l) => lines.push(l));
    const proxy = startMcpStdioProxy(h.gateway, {
      command: process.execPath,
      args: [path.resolve(__dirname, "fixtures", "fake-mcp-server.mjs")],
      env: { ...process.env, FAKE_MCP_LOG: logFile },
      input,
      output,
    });
    input.write(`﻿${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_orders", arguments: { q: "eof" } } })}\n`);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "refund_order", arguments: { amount: 999 } } })}\n`);
    input.end(); // client goes away immediately
    await proxy.exited;
    await sleep(50);
    const byId = new Map(lines.map((l) => JSON.parse(l)).map((m) => [m.id, m]));
    assert.equal(byId.get(1)?.result?.content?.[0]?.text, 'ran search_orders {"q":"eof"}', "the allowed call was delivered");
    assert.equal(byId.get(2)?.result?._meta?.["mont/decision"], "EXPIRED", "the held call expired with the client");
    const calls = fs.readFileSync(logFile, "utf8").trim().split("\n").map((l) => JSON.parse(l).name);
    assert.deepEqual(calls, ["search_orders"], "the held call never reached the server");
  });

  test("held MCP calls of a dead process are expired at startup; live owners are left alone", async () => {
    const h = await makeHarness({ rules: MCP_RULES });
    const insert = (owner: string) =>
      sqliteRun(
        h.dbPath,
        `INSERT INTO pending_actions (timestamp, method, path, status, expires_at, kind, owner) VALUES (?, 'MCP', '/api/mcp/tools/refund_order', 'PENDING', ?, 'mcp', ?)`,
        [new Date().toISOString(), Date.now() + 3600_000, owner]
      );
    await insert(`${os.hostname()}:999999:deadbeef`);
    await insert(`${os.hostname()}:${process.pid}:livebeef`);
    const restarted = await makeHarness({ dir: h.dir });
    const rows = await sqliteAll<{ owner: string; status: string }>(restarted.dbPath, "SELECT owner, status FROM pending_actions WHERE kind = 'mcp' ORDER BY id");
    assert.equal(rows[0].status, "EXPIRED");
    assert.equal(rows[1].status, "PENDING");
    void ADMIN_TOKEN;
  });
});
