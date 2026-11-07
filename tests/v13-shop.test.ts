/**
 * v1.3 shop-owner suite: spending budgets, duplicate-action protection, emergency lockdown /
 * approval-only, business hours, Telegram bot commands, security alerts + daily digest,
 * "money protected" summary and CSV export.
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import type { Request, Response } from "express";
import { createMcpHttpProxy } from "../src/gateway";
import type { Rules } from "../src/gateway";
import { isWithinBusinessHours, localTime } from "../src/core/operatingMode";
import { extractAmount } from "../src/core/guards";
import fs from "fs";
import { closeServer, fakeTelegram, listen, makeHarness, onCleanup, pendingStatus, postJson, runCleanups, sleep, tempDir, waitFor } from "./helpers";

after(runCleanups);

/** A webhook receiver that records every notification / alert the gateway sends. */
async function receiver(): Promise<{ url: string; events: Array<{ event: string; title?: string; lines?: string[]; raw: string }> }> {
  const events: Array<{ event: string; title?: string; lines?: string[]; raw: string }> = [];
  const server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        const j = JSON.parse(data) as { event: string; title?: string; lines?: string[] };
        events.push({ ...j, raw: data });
      } catch {
        events.push({ event: "unparsed", raw: data });
      }
      res.end("ok");
    });
  });
  const port = await listen(server);
  onCleanup(() => closeServer(server));
  return { url: `http://127.0.0.1:${port}/hook`, events };
}

const statusOf = (p: Promise<globalThis.Response>): Promise<number> =>
  p.then(async (r) => {
    await r.arrayBuffer();
    return r.status;
  });

// ---------------------------------------------------------------------------
// 1. Spending budgets
// ---------------------------------------------------------------------------
describe("1. spending budgets", () => {
  test("cumulative cap, strict amounts, approved spend counts, survives restart, alerts the owner", async () => {
    const hook = await receiver();
    const rules: Rules = {
      "POST /api/refund": {
        mode: "ALLOW",
        description: "",
        budget: { field: "body.amount", max: 300, windowMinutes: 60, per: "global", onExceed: "REQUIRE_APPROVAL" },
      },
    };
    const dir = tempDir(); // outlives the first gateway so it can be restarted on the same data
    onCleanup(async () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const h = await makeHarness({ rules, dir });
    await h.admin("POST", "/setup", { notifications: { webhook: { enabled: true, url: hook.url } } });

    for (let i = 0; i < 3; i++) assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { orderId: i, amount: 100 })), 200);
    const over = await postJson(`${h.base}/api/refund`, { orderId: 9, amount: 50 });
    assert.equal(over.status, 202, "the 4th refund would exceed $300/hour: held for a human");
    const { approvalId, reason } = (await over.json()) as { approvalId: number; reason: string };
    assert.match(reason, /Spending budget reached: 300 of 300/);
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { orderId: 10 })), 202, "missing amount cannot be checked: held");
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { orderId: 11, amount: "5" })), 202, "text amounts are not numbers: held");
    assert.equal(h.hits.length, 3);

    let usage = (await h.admin("GET", "/guards/usage")).data;
    assert.deepEqual([usage[0].spent, usage[0].remaining], [300, 0]);

    // A human approves the over-budget refund: it runs, and it counts toward the budget.
    assert.equal((await h.admin("POST", `/approvals/${approvalId}/decide`, { decision: "APPROVE" })).status, 200);
    usage = (await h.admin("GET", "/guards/usage")).data;
    assert.equal(usage[0].spent, 350);

    await waitFor(() => hook.events.find((e) => e.event === "alert" && /Spending budget reached/.test(e.title ?? "")), 5000, "budget alert");

    // Restart: the ledger is in SQLite, so the budget is still used up.
    await h.close();
    const restarted = await makeHarness({ dir });
    assert.equal(await statusOf(postJson(`${restarted.base}/api/refund`, { orderId: 12, amount: 1 })), 202);
  });

  test("50-wide concurrent burst cannot overspend (per-rule lock)", async () => {
    const h = await makeHarness({
      rules: {
        "POST /api/payout": { mode: "ALLOW", description: "", budget: { field: "body.amount", max: 200, windowMinutes: 60, per: "global", onExceed: "BLOCK" } },
      },
    });
    const statuses = await Promise.all(Array.from({ length: 50 }, (_, i) => statusOf(postJson(`${h.base}/api/payout`, { n: i, amount: 50 }))));
    assert.equal(statuses.filter((s) => s === 200).length, 4);
    assert.equal(statuses.filter((s) => s === 403).length, 46);
    assert.equal(h.hits.length, 4, "exactly $200 left the gateway");
  });

  test("per-agent budgets: each agent key has its own allowance", async () => {
    const h = await makeHarness({
      rules: {
        "POST /api/credit": { mode: "ALLOW", description: "", budget: { field: "body.amount", max: 100, windowMinutes: 60, per: "caller", onExceed: "BLOCK" } },
      },
    });
    const a = (await h.admin("POST", "/agent-keys", { name: "support-bot" })).data.key as string;
    const b = (await h.admin("POST", "/agent-keys", { name: "sales-bot" })).data.key as string;
    assert.equal(await statusOf(postJson(`${h.base}/api/credit`, { amount: 60 }, { "x-agent-key": a })), 200);
    assert.equal(await statusOf(postJson(`${h.base}/api/credit`, { amount: 60 }, { "x-agent-key": a })), 403);
    assert.equal(await statusOf(postJson(`${h.base}/api/credit`, { amount: 60 }, { "x-agent-key": b })), 200);
    const usage = (await h.admin("GET", "/guards/usage")).data;
    assert.equal(usage[0].per, "caller");
    assert.equal(usage[0].spent, 60, "per-caller usage reports the highest single caller");
  });

  test("rules API validates budgets, keeps them when the Rules tab saves, and invalid files fail closed", async () => {
    const h = await makeHarness({ rules: { "POST /api/x": { mode: "ALLOW", description: "" } } });
    const bad = await h.admin("POST", "/rules", { "POST /api/x": { mode: "ALLOW", budget: { field: "amount", max: 5, windowMinutes: 1 } } });
    assert.equal(bad.status, 400);
    const good = await h.admin("POST", "/rules", {
      "POST /api/x": { mode: "ALLOW", budget: { field: "body.amount", max: 5, windowMinutes: 1 }, dedupe: { fields: ["body.id"], windowMinutes: 5 } },
    });
    assert.equal(good.status, 200);
    assert.deepEqual(good.data.rules["POST /api/x"].budget, { field: "body.amount", max: 5, windowMinutes: 1, per: "global", onExceed: "REQUIRE_APPROVAL" });
    // The Rules tab only sends mode/description: the guards must survive.
    const toggled = await h.admin("POST", "/rules", { "POST /api/x": { mode: "REQUIRE_APPROVAL", description: "edited" } });
    assert.ok(toggled.data.rules["POST /api/x"].budget && toggled.data.rules["POST /api/x"].dedupe);
    const cleared = await h.admin("POST", "/rules", { "POST /api/x": { mode: "ALLOW", budget: null } });
    assert.equal(cleared.data.rules["POST /api/x"].budget, undefined);

    const broken = await makeHarness({
      rules: { "POST /api/y": { mode: "ALLOW", description: "", budget: { field: "body.amount", max: -1, windowMinutes: 0 } } as unknown as Rules[string] },
    });
    assert.equal(await statusOf(postJson(`${broken.base}/api/y`, { amount: 1 })), 403, "unreadable budget = BLOCK");
  });

  test("extractAmount finds money fields for the audit log", () => {
    assert.equal(extractAmount({ amount: 12.5 }), 12.5);
    assert.equal(extractAmount({ order: { total: 99 } }), 99);
    assert.equal(extractAmount({ amount: "12" }), null);
    assert.equal(extractAmount([1, 2]), null);
  });
});

// ---------------------------------------------------------------------------
// 2. Duplicate-action protection
// ---------------------------------------------------------------------------
describe("2. duplicate-action protection", () => {
  test("same order refunded twice is refused, even in a concurrent burst; other orders pass", async () => {
    const h = await makeHarness({
      rules: {
        "POST /api/refund": { mode: "ALLOW", description: "", dedupe: { fields: ["body.orderId"], windowMinutes: 1440, onDuplicate: "BLOCK" } },
      },
    });
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { orderId: "A", amount: 10 })), 200);
    const dup = await postJson(`${h.base}/api/refund`, { orderId: "A", amount: 10 });
    assert.equal(dup.status, 403);
    assert.match(((await dup.json()) as { message: string }).message, /duplicate/i);
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { orderId: "B", amount: 10 })), 200);

    const burst = await Promise.all(Array.from({ length: 8 }, () => statusOf(postJson(`${h.base}/api/refund`, { orderId: "C", amount: 10 }))));
    assert.deepEqual([burst.filter((s) => s === 200).length, burst.filter((s) => s === 403).length], [1, 7]);

    // Without the identifying field the action cannot be identified, so it is not deduplicated.
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { amount: 1 })), 200);
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { amount: 1 })), 200);
    assert.equal(h.hits.length, 5);
  });

  test("duplicates of a request waiting for approval are refused; after a rejection a retry is allowed", async () => {
    const h = await makeHarness({
      rules: {
        "POST /api/big-refund": { mode: "REQUIRE_APPROVAL", description: "", dedupe: { fields: ["body.orderId"], windowMinutes: 1440, onDuplicate: "BLOCK" } },
      },
    });
    const first = await postJson(`${h.base}/api/big-refund`, { orderId: "Z", amount: 900 });
    assert.equal(first.status, 202);
    const { approvalId } = (await first.json()) as { approvalId: number };
    assert.equal(await statusOf(postJson(`${h.base}/api/big-refund`, { orderId: "Z", amount: 900 })), 403);
    await h.admin("POST", `/approvals/${approvalId}/decide`, { decision: "REJECT" });
    assert.equal(await statusOf(postJson(`${h.base}/api/big-refund`, { orderId: "Z", amount: 900 })), 202, "rejected attempts do not count as duplicates");
  });
});

// ---------------------------------------------------------------------------
// 3. Emergency modes
// ---------------------------------------------------------------------------
describe("3. emergency lockdown / approval-only", () => {
  const rules: Rules = {
    "GET /api/orders": { mode: "ALLOW", description: "" },
    "POST /api/refund": { mode: "ALLOW", description: "" },
    "POST /api/hold": { mode: "REQUIRE_APPROVAL", description: "" },
  };

  test("approval-only holds writes, lockdown refuses everything and freezes approvals, resume restores", async () => {
    const hook = await receiver();
    const h = await makeHarness({ rules });
    await h.admin("POST", "/setup", { notifications: { webhook: { enabled: true, url: hook.url } } });
    const held = (await (await postJson(`${h.base}/api/hold`, { amount: 5 })).json()) as { approvalId: number };

    assert.equal((await h.admin("POST", "/emergency", { mode: "panic" })).status, 400);
    assert.equal((await h.admin("POST", "/emergency", { mode: "approval_only", reason: "suspicious refunds" })).status, 200);
    assert.equal(await statusOf(fetch(`${h.base}/api/orders`)), 200, "reads still work");
    const w = await postJson(`${h.base}/api/refund`, { amount: 5 });
    assert.equal(w.status, 202);
    assert.equal(((await w.json()) as { reason: string }).reason, "approval-only mode");

    const lock = await h.admin("POST", "/emergency", { mode: "lockdown", reason: "prompt injection found" });
    assert.equal(lock.data.mode, "lockdown");
    assert.equal(lock.data.changedBy, "api-token-admin");
    const refused = await fetch(`${h.base}/api/orders`);
    assert.equal(refused.status, 403);
    assert.match(((await refused.json()) as { message: string }).message, /lockdown/);
    assert.equal((await h.admin("POST", `/approvals/${held.approvalId}/decide`, { decision: "APPROVE" })).status, 409, "nothing executes in lockdown");
    assert.equal((await h.admin("POST", `/approvals/${held.approvalId}/decide`, { decision: "REJECT" })).status, 200, "rejecting is still possible");

    await h.admin("POST", "/emergency", { mode: "normal" });
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { amount: 5 })), 200);
    assert.equal(h.hits.filter((x) => x.key === "POST /api/refund").length, 1);

    await waitFor(() => hook.events.filter((e) => /Gateway mode changed/.test(e.title ?? "")).length >= 3, 5000, "3 mode-change alerts");
  });

  test("a lockdown set in one process reaches every process sharing the database", async () => {
    const a = await makeHarness({ rules, gatewayOptions: { emergencyRefreshMs: 100 } });
    const b = await makeHarness({ dir: a.dir, gatewayOptions: { emergencyRefreshMs: 100 } });
    assert.equal(await statusOf(fetch(`${b.base}/api/orders`)), 200);
    await a.admin("POST", "/emergency", { mode: "lockdown" });
    await waitFor(async () => (await statusOf(fetch(`${b.base}/api/orders`))) === 403, 3000, "process B locked down");
    await a.admin("POST", "/emergency", { mode: "normal" });
    await waitFor(async () => (await statusOf(fetch(`${b.base}/api/orders`))) === 200, 3000, "process B resumed");
  });

  test("MCP tool calls obey lockdown and approval-only too", async () => {
    const up = express();
    up.use(express.json());
    up.post("/mcp", (req: Request, res: Response) => res.json({ jsonrpc: "2.0", id: req.body.id, result: { content: [{ type: "text", text: "ran" }] } }));
    const upServer = http.createServer(up);
    const upPort = await listen(upServer);
    onCleanup(() => closeServer(upServer));
    const h = await makeHarness({
      rules: { "MCP /api/mcp/tools/search": { mode: "ALLOW", description: "" } },
      mount: (app, gw) => app.use("/mcp", createMcpHttpProxy(gw, { upstreamUrl: `http://127.0.0.1:${upPort}/mcp`, approvalWaitMs: 300 })),
    });
    const call = async () =>
      ((await (await postJson(`${h.base}/mcp`, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search", arguments: {} } })).json()) as any).result;
    assert.equal((await call()).content[0].text, "ran");
    await h.admin("POST", "/emergency", { mode: "approval_only" });
    assert.equal((await call())._meta["mont/decision"], "EXPIRED", "held for approval (and expired unanswered)");
    await h.admin("POST", "/emergency", { mode: "lockdown" });
    assert.equal((await call())._meta["mont/decision"], "BLOCK");
  });
});

// ---------------------------------------------------------------------------
// 4. Business hours
// ---------------------------------------------------------------------------
describe("4. business hours", () => {
  test("time zone maths, including DST and overnight shifts", () => {
    const weekdays = { enabled: true, days: [1, 2, 3, 4, 5], start: "09:00", end: "17:00" };
    assert.equal(isWithinBusinessHours(weekdays, "America/New_York", new Date("2026-11-06T15:00:00Z")), true, "Fri 10:00 EST");
    assert.equal(isWithinBusinessHours(weekdays, "America/New_York", new Date("2026-11-06T23:00:00Z")), false, "Fri 18:00 EST");
    assert.equal(isWithinBusinessHours(weekdays, "America/New_York", new Date("2026-11-07T15:00:00Z")), false, "Saturday");
    assert.equal(isWithinBusinessHours(weekdays, "America/New_York", new Date("2026-07-01T13:30:00Z")), true, "Wed 09:30 EDT (summer time)");
    assert.equal(isWithinBusinessHours(weekdays, "Asia/Kolkata", new Date("2026-11-06T03:00:00Z")), false, "Fri 08:30 IST: before opening");
    assert.equal(isWithinBusinessHours(weekdays, "Asia/Kolkata", new Date("2026-11-06T04:00:00Z")), true, "Fri 09:30 IST");
    const nights = { enabled: true, days: [5], start: "22:00", end: "06:00" };
    assert.equal(isWithinBusinessHours(nights, "UTC", new Date("2026-11-07T03:00:00Z")), true, "Sat 03:00 belongs to Friday's night shift");
    assert.equal(isWithinBusinessHours(nights, "UTC", new Date("2026-11-08T03:00:00Z")), false, "Sun 03:00: Saturday has no shift");
    assert.deepEqual(localTime("Asia/Kolkata", new Date("2026-11-06T20:00:00Z")), { weekday: 6, hour: 1, minute: 30, date: "2026-11-07" });
  });

  test("outside hours, writes the rules would allow are held; reads are not", async () => {
    const h = await makeHarness({ rules: { "GET /api/orders": { mode: "ALLOW", description: "" }, "POST /api/refund": { mode: "ALLOW", description: "" } } });
    const today = localTime("UTC").weekday;
    const closed = await h.admin("POST", "/setup", { timezone: "UTC", schedule: { enabled: true, days: [(today + 3) % 7], start: "09:00", end: "17:00" } });
    assert.equal(closed.status, 200);
    assert.equal(closed.data.withinBusinessHours, false);
    const held = await postJson(`${h.base}/api/refund`, { amount: 5 });
    assert.equal(held.status, 202);
    assert.equal(((await held.json()) as { reason: string }).reason, "outside business hours");
    assert.equal(await statusOf(fetch(`${h.base}/api/orders`)), 200);

    // start == end means "all day" on the listed days.
    await h.admin("POST", "/setup", { schedule: { days: [today], start: "00:00", end: "00:00" } });
    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { amount: 5 })), 200);

    assert.equal((await h.admin("POST", "/setup", { timezone: "Mars/Olympus" })).status, 400);
    assert.equal((await h.admin("POST", "/setup", { schedule: { start: "25:00" } })).status, 400);
  });
});

// ---------------------------------------------------------------------------
// 5. Telegram bot commands
// ---------------------------------------------------------------------------
describe("5. Telegram bot commands", () => {
  test("/status /pending /lockdown /resume from the owner's phone; strangers and other chats are ignored", async () => {
    const token = "123456789:AAH_cmd_token_abcdefghijklmnopqrstuvw";
    const tg = await fakeTelegram(token);
    const h = await makeHarness({
      rules: { "POST /api/hold": { mode: "REQUIRE_APPROVAL", description: "" } },
      gatewayOptions: { telegramApiBase: tg.base, telegramPollTimeoutSec: 1, emergencyRefreshMs: 100 },
    });
    await h.admin("POST", "/setup", { notifications: { telegram: { enabled: true, mode: "polling", botToken: token, chatId: "-100555", approverIds: "777" } } });
    await waitFor(async () => (await h.admin("GET", "/setup")).data.bridges.telegram.state === "connected", 8000, "telegram connected");

    const say = (text: string, userId = 777, chatId = -100555) =>
      tg.push({ message: { message_id: Math.floor(Math.random() * 1e6), text, from: { id: userId, username: `u${userId}` }, chat: { id: chatId } } });
    const repliesMatching = (re: RegExp) => tg.sent.filter((m) => re.test(String(m.text)));

    say("/status");
    await waitFor(() => repliesMatching(/Mont gateway status[\s\S]*Mode: 🟢 Normal/).length === 1, 5000, "/status reply");

    say("/lockdown fraud spotted", 555);
    await waitFor(() => repliesMatching(/not on the approver list/).length === 1, 5000, "stranger refused");
    say("/lockdown fraud spotted", 777, -100999);
    await sleep(500);
    assert.equal((await h.admin("GET", "/emergency")).data.mode, "normal");

    say("/lockdown fraud spotted");
    await waitFor(async () => (await h.admin("GET", "/emergency")).data.mode === "lockdown", 5000, "lockdown via Telegram");
    const state = (await h.admin("GET", "/emergency")).data;
    assert.equal(state.reason, "fraud spotted");
    assert.equal(state.changedBy, "telegram:@u777");

    say("/resume");
    await waitFor(async () => (await h.admin("GET", "/emergency")).data.mode === "normal", 5000, "resume via Telegram");

    const queued = (await (await postJson(`${h.base}/api/hold`, { amount: 42 })).json()) as { approvalId: number };
    const before = tg.sent.length;
    say("/pending");
    const card = await waitFor(
      () => tg.sent.slice(before).find((m) => String(m.text).includes(`#${queued.approvalId}`) && m.reply_markup),
      5000,
      "/pending card with buttons"
    );
    assert.match(card.reply_markup.inline_keyboard[0][0].callback_data, /^mont:A:\d+:/);

    say("/frobnicate");
    await waitFor(() => repliesMatching(/Unknown command/).length === 1, 5000, "unknown command reply");
    assert.equal(await pendingStatus(h.dbPath, queued.approvalId), "PENDING");
  });
});

// ---------------------------------------------------------------------------
// 6. Alerts, digest, protection summary, CSV export
// ---------------------------------------------------------------------------
describe("6. alerts, digest, money-protected summary, CSV export", () => {
  test("attack burst alert (once), digest on demand and on schedule (once per day), summary and CSV", async () => {
    const hook = await receiver();
    const h = await makeHarness({
      rules: {
        "POST /api/refund": {
          mode: "ALLOW",
          description: "",
          policies: [{ name: "huge", when: [{ field: "body.amount", op: ">", value: 1000 }], mode: "BLOCK" }],
        },
      },
      gatewayOptions: { alertCheckIntervalMs: 100 },
    });
    await h.admin("POST", "/setup", {
      timezone: "UTC",
      alerts: { enabled: true, burstThreshold: 5, burstWindowMinutes: 5 },
      notifications: { webhook: { enabled: true, url: hook.url } },
    });

    assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { amount: 40 })), 200);
    for (let i = 0; i < 6; i++) {
      assert.equal(await statusOf(postJson(`${h.base}/api/refund`, { amount: 5000 }, { "user-agent": '=HYPERLINK("http://evil.test","click")' })), 403);
    }
    const burst = await waitFor(() => hook.events.find((e) => /agent requests refused/.test(e.title ?? "")), 5000, "burst alert");
    assert.ok(burst.lines?.some((l) => l.includes("POST /api/refund")));
    await sleep(500);
    assert.equal(hook.events.filter((e) => /agent requests refused/.test(e.title ?? "")).length, 1, "debounced: one alert per 15 minutes");

    const summary = (await h.admin("GET", "/protection/summary?hours=24")).data;
    assert.equal(summary.counts.BLOCKED, 6);
    assert.equal(summary.moneyProtected, 30000);
    assert.equal(summary.moneyExecuted, 40);
    assert.equal(summary.topBlocked[0].path, "/api/refund");
    assert.equal(summary.emergency.mode, "normal");

    const digestNow = await h.admin("POST", "/alerts/digest");
    assert.equal(digestNow.status, 200);
    const d1 = await waitFor(() => hook.events.find((e) => e.title === "Mont daily digest"), 5000, "manual digest");
    assert.ok(d1.lines?.some((l) => l.includes("Money protected: 30,000")));

    // Scheduled digest at the current UTC hour: sent once, not on every check.
    await h.admin("POST", "/setup", { alerts: { digestHour: localTime("UTC").hour } });
    await waitFor(() => hook.events.filter((e) => e.title === "Mont daily digest").length === 2, 5000, "scheduled digest");
    await sleep(500);
    assert.equal(hook.events.filter((e) => e.title === "Mont daily digest").length, 2);

    const csv = await fetch(`${h.base}/api/agent-admin/logs/export.csv?status=BLOCKED`, { headers: { "x-admin-token": "v12-suite-admin-token-0123456789abcdef" } });
    assert.equal(csv.status, 200);
    assert.match(csv.headers.get("content-type") ?? "", /text\/csv/);
    assert.match(csv.headers.get("content-disposition") ?? "", /attachment; filename="mont-audit-/);
    const text = (await csv.text()).replace(/^\uFEFF/, "");
    const lines = text.trim().split("\n");
    assert.equal(lines[0], "id,timestamp,method,path,status,amount,agent_key,caller_ip,user_agent,action_id,detail");
    assert.equal(lines.length, 7);
    assert.ok(lines[1].includes(`"'=HYPERLINK(""http://evil.test"",""click"")"`), "formula injection neutralised");
    assert.ok(lines.slice(1).every((l) => l.includes(",BLOCKED,5000,")));
  });
});
