/**
 * v2.1 owner UX: agent justifications on approval notifications, and the zero-LLM daily digest.
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import type { Request, Response } from "express";
import { createMcpHttpProxy } from "../src/gateway";
import { justificationFromHeaders, justificationFromMcpMeta, justificationFromPayload } from "../src/core/justification";
import { digestSentence } from "../src/core/digest";
import { NEVER_FORWARD } from "../src/core/constants";
import { closeServer, fakeTelegram, listen, makeHarness, onCleanup, postJson, runCleanups, sqliteGet, sqliteRun, waitFor } from "./helpers";

after(runCleanups);

// ---------------------------------------------------------------------------
// 1. Agent justifications
// ---------------------------------------------------------------------------
describe("1. agent justifications", () => {
  test("extraction priority: x-mont-justification > x-agent-reason; justification > reason > summary", () => {
    const h = (m: Record<string, string>) => (name: string) => m[name];
    assert.equal(justificationFromHeaders(h({ "x-mont-justification": "A", "x-agent-reason": "B" })), "A");
    assert.equal(justificationFromHeaders(h({ "x-agent-reason": "B" })), "B");
    assert.equal(justificationFromHeaders(h({ "x-mont-justification": "   " })), null);
    assert.equal(justificationFromPayload({ summary: "S", reason: "R", justification: "J" }), "J");
    assert.equal(justificationFromPayload({ summary: "S", reason: "R" }), "R");
    assert.equal(justificationFromPayload({ summary: "line1\nline2\u0007" }), "line1 line2");
    assert.equal(justificationFromPayload({ reason: 42, summary: "S" }), "S", "non-strings are skipped");
    assert.equal(justificationFromPayload(["reason"]), null);
    assert.equal(justificationFromMcpMeta({ "mont/justification": "MJ", "mont/reason": "MR" }), "MJ");
    assert.equal(justificationFromPayload({ reason: "x".repeat(5000) })!.length <= 1000, true, "capped");
  });

  test("HTTP: header and body justifications are stored, shown above the buttons, and never forwarded", async () => {
    const token = "123456789:AAH_justify_token_abcdefghijklmnopqrs";
    const tg = await fakeTelegram(token);
    // Fake Slack Web API: records chat.postMessage (Socket Mode itself is not needed to send).
    const slack = { bodies: [] as any[] };
    const sApp = express();
    sApp.use(express.json());
    sApp.post("/chat.postMessage", (req: Request, res: Response) => {
      slack.bodies.push(req.body);
      res.json({ ok: true, ts: "1700000000.001", channel: req.body.channel });
    });
    sApp.post("/apps.connections.open", (_req: Request, res: Response) => res.json({ ok: false, error: "not_in_test" }));
    const sServer = http.createServer(sApp);
    const sPort = await listen(sServer);
    onCleanup(() => closeServer(sServer));
    const h = await makeHarness({
      rules: {
        "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" },
      },
      gatewayOptions: { telegramApiBase: tg.base, telegramPollTimeoutSec: 0, slackApiBase: `http://127.0.0.1:${sPort}` },
    });
    const saved = await h.admin("POST", "/setup", {
      notifications: {
        telegram: { enabled: true, mode: "polling", botToken: token, chatId: "-100777" },
        slack: { enabled: true, mode: "socket", botToken: "xoxb-1234-5678-abcdefgh", appToken: "xapp-1-A0123-4567-abcdef", channelId: "C0123ABCD" },
      },
    });
    assert.equal(saved.status, 200, JSON.stringify(saved.data));

    // (a) header wins over a body field
    const r1 = await postJson(`${h.base}/api/refund`, { orderId: "1001", amount: 40, reason: "body reason" }, { "x-mont-justification": "Customer was double charged on #1001" });
    assert.equal(r1.status, 202);
    const id1 = ((await r1.json()) as { approvalId: number }).approvalId;
    // (b) body field only
    const r2 = await postJson(`${h.base}/api/refund`, { orderId: "1002", amount: 15, summary: "Late delivery goodwill credit" });
    const id2 = ((await r2.json()) as { approvalId: number }).approvalId;
    // (c) nothing given
    const r3 = await postJson(`${h.base}/api/refund`, { orderId: "1003", amount: 5 });
    const id3 = ((await r3.json()) as { approvalId: number }).approvalId;

    const reasonOf = async (id: number) => (await sqliteGet<{ agent_reason: string | null }>(h.dbPath, "SELECT agent_reason FROM pending_actions WHERE id = ?", [id]))?.agent_reason;
    assert.equal(await reasonOf(id1), "Customer was double charged on #1001");
    assert.equal(await reasonOf(id2), "Late delivery goodwill credit");
    assert.equal(await reasonOf(id3), null);

    // Telegram: the justification is the last thing in the text, i.e. directly above the inline buttons.
    const tgMsg = await waitFor(() => tg.sent.find((m) => String(m.text).includes(`#${id1}`)), 5000, "telegram notice");
    const text = String(tgMsg.text);
    assert.ok(text.includes("Agent's Justification"), text);
    assert.ok(text.indexOf("Agent's Justification") > text.indexOf("</pre>"), "after the payload");
    assert.ok(text.trimEnd().endsWith("Customer was double charged on #1001</blockquote>"), text);
    assert.ok(tgMsg.reply_markup.inline_keyboard[0].length === 2, "approve / reject buttons attached");
    const tgNone = await waitFor(() => tg.sent.find((m) => String(m.text).includes(`#${id3}`)), 5000, "telegram notice 3");
    assert.match(String(tgNone.text), /Agent's Justification:<\/b> <i>none given/);

    // Slack: the justification block sits immediately before the actions block.
    const sl = await waitFor(() => slack.bodies.find((b) => String(b.text).includes(`#${id2}`)), 5000, "slack notice");
    const actionsAt = sl.blocks.findIndex((b: { type: string }) => b.type === "actions");
    assert.ok(actionsAt > 0, JSON.stringify(sl.blocks));
    assert.match(sl.blocks[actionsAt - 1].text.text, /Agent's Justification\*\n>Late delivery goodwill credit/);

    // The header is gateway-internal: proxy mode never forwards it upstream.
    assert.ok(NEVER_FORWARD.has("x-mont-justification"));
  });

  test("MCP: a justification field in the tool arguments (or _meta) reaches the approver", async () => {
    const up = express();
    up.use(express.json());
    up.post("/mcp", (req: Request, res: Response) => res.json({ jsonrpc: "2.0", id: req.body.id, result: { content: [{ type: "text", text: "ok" }] } }));
    const upServer = http.createServer(up);
    const upPort = await listen(upServer);
    onCleanup(() => closeServer(upServer));
    const h = await makeHarness({
      rules: { "MCP /api/mcp/tools/refund_order": { mode: "REQUIRE_APPROVAL", description: "" } },
      mount: (app, gw) => app.use("/mcp", createMcpHttpProxy(gw, { upstreamUrl: `http://127.0.0.1:${upPort}/mcp`, approvalWaitMs: 10_000 })),
    });
    const ac = new AbortController();
    onCleanup(async () => ac.abort());
    void postJson(
      `${h.base}/mcp`,
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "refund_order", arguments: { orderId: "#9", amount: 90, justification: "Item arrived broken (photo in ticket 55)" } } },
      {},
      ac.signal
    ).catch(() => undefined);
    const row = await waitFor(async () => ((await h.admin("GET", "/approvals")).data as any[]).find((a) => a.kind === "mcp" && a.status === "PENDING"), 5000, "held call");
    assert.equal(row.agent_reason, "Item arrived broken (photo in ticket 55)");
    await h.admin("POST", `/approvals/${row.id}/decide`, { decision: "REJECT" });

    void postJson(
      `${h.base}/mcp`,
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "refund_order", arguments: { orderId: "#10", amount: 5 }, _meta: { "mont/justification": "Meta says why" } } },
      {},
      ac.signal
    ).catch(() => undefined);
    const row2 = await waitFor(async () => ((await h.admin("GET", "/approvals")).data as any[]).find((a) => a.kind === "mcp" && a.status === "PENDING"), 5000, "held call 2");
    assert.equal(row2.agent_reason, "Meta says why");
    await h.admin("POST", `/approvals/${row2.id}/decide`, { decision: "REJECT" });
  });
});

// ---------------------------------------------------------------------------
// 2. Daily digest
// ---------------------------------------------------------------------------
describe("2. zero-LLM daily digest", () => {
  test("counts requests, risky calls and money prevented from the last 24h only", async () => {
    const h = await makeHarness({
      rules: {
        "POST /api/refund": {
          mode: "ALLOW",
          description: "",
          policies: [{ name: "big refunds", when: [{ field: "body.amount", op: ">", value: 100 }], mode: "BLOCK" }],
        },
        "POST /api/order": { mode: "REQUIRE_APPROVAL", description: "" },
        "POST /api/lookup": { mode: "ALLOW", description: "" },
      },
    });
    const ok = async (p: Promise<globalThis.Response>) => (await p).status;
    assert.equal(await ok(postJson(`${h.base}/api/lookup`, { q: 1 })), 200);
    assert.equal(await ok(postJson(`${h.base}/api/refund`, { amount: 20 })), 200);
    assert.equal(await ok(postJson(`${h.base}/api/refund`, { amount: 500 })), 403, "blocked by the tier");
    assert.equal(await ok(postJson(`${h.base}/api/refund`, { amount: 250.5 })), 403, "blocked by the tier");
    assert.equal(await ok(postJson(`${h.base}/api/nope`, { amount: 9999 })), 403, "default deny, no rule");
    const held = await postJson(`${h.base}/api/order`, { price: 75, sku: "A" });
    const heldId = ((await held.json()) as { approvalId: number }).approvalId;
    await postJson(`${h.base}/api/order`, { price: 10, sku: "B" }); // stays pending
    assert.equal((await h.admin("POST", `/approvals/${heldId}/decide`, { decision: "REJECT" })).status, 200);

    // An old row outside the window must not count.
    await sqliteRun(h.dbPath, "INSERT INTO agent_logs (timestamp, method, path, status, user_agent, amount) VALUES (?, 'POST', '/api/refund', 'BLOCKED', 'old', 1000000)", [
      new Date(Date.now() - 48 * 3600_000).toISOString(),
    ]);

    const res = await h.admin("GET", "/audit/digest");
    assert.equal(res.status, 200, JSON.stringify(res.data));
    const d = res.data;
    assert.equal(d.totalRequests, 7, "lookup + 3 refunds + nope + 2 orders (the human decision is not a request)");
    assert.equal(d.blocked, 3);
    assert.equal(d.rejected, 1);
    assert.equal(d.riskyCalls, 4);
    assert.equal(d.moneyPrevented, 500 + 250.5 + 9999 + 75);
    assert.equal(d.pendingApprovals, 1);
    assert.equal(
      d.summary,
      "In the last 24 hours, Mont processed 7 actions and blocked 4 risky calls (3 by your rules, 1 rejected by you), preventing an estimated $10,824.50 in unauthorized actions. You have 1 action pending approval."
    );
  });

  test("template wording for quiet days and calls without amounts", () => {
    const base = { windowHours: 24, since: "", generatedAt: "", workspaceId: null, riskyCallsWithAmount: 0 };
    assert.equal(
      digestSentence({ ...base, totalRequests: 0, blocked: 0, rateLimited: 0, rejected: 0, riskyCalls: 0, moneyPrevented: 0, pendingApprovals: 0 }),
      "Mont saw no agent actions in the last 24 hours. Nothing is waiting for your approval."
    );
    assert.equal(
      digestSentence({ ...base, totalRequests: 12, blocked: 0, rateLimited: 2, rejected: 0, riskyCalls: 2, moneyPrevented: 0, pendingApprovals: 3 }),
      "In the last 24 hours, Mont processed 12 actions and blocked 2 risky calls (none of them carried a dollar amount). You have 3 actions pending approval."
    );
  });
});

// ---------------------------------------------------------------------------
// 3. Unknown endpoints (discovery)
// ---------------------------------------------------------------------------
describe("3. unknown endpoints", () => {
  test("a call with no matching rule is refused, audited with its payload, and listed by ?unknown=1", async () => {
    const h = await makeHarness({ rules: { "GET /api/known": { mode: "ALLOW", description: "" }, "POST /api/blocked": { mode: "BLOCK", description: "" } } });

    const unknown = await postJson(`${h.base}/api/never-defined`, { orderId: 7, amount: 12 });
    assert.equal(unknown.status, 403, "default deny");
    await unknown.arrayBuffer();
    // An explicit BLOCK rule is a known endpoint, so it must not show up as unknown.
    await (await postJson(`${h.base}/api/blocked`, { x: 1 })).arrayBuffer();
    await (await fetch(`${h.base}/api/known`)).arrayBuffer();
    assert.equal(h.hits.length, 1, "only the allowed call reached the upstream");

    const rows = (await h.admin("GET", "/logs?unknown=1")).data as Array<{ method: string; path: string; status: string; detail: string; has_snapshot: boolean }>;
    assert.equal(rows.length, 1);
    assert.deepEqual([rows[0].method, rows[0].path, rows[0].status, rows[0].detail], ["POST", "/api/never-defined", "BLOCKED", "default-deny"]);
    assert.equal(rows[0].has_snapshot, true, "the payload is kept so the admin can see what the agent tried");

    const all = (await h.admin("GET", "/logs")).data as unknown[];
    assert.equal(all.length, 3, "without the filter every row is listed");
  });
});

// ---------------------------------------------------------------------------
// 4. Approval idempotency
// ---------------------------------------------------------------------------
describe("4. approval idempotency", () => {
  type Decided = { status: number; data: { status?: string; message?: string; alreadyTaken?: boolean; decided_by?: string } };
  const queue = async (base: string, n: number): Promise<number> => {
    const r = await postJson(`${base}/api/refund`, { orderId: `ORD-${n}`, amount: 500 });
    assert.equal(r.status, 202);
    return ((await r.json()) as { approvalId: number }).approvalId;
  };

  test("a second decision is refused with 'Action already taken' and changes nothing", async () => {
    const h = await makeHarness({ rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } } });
    const id = await queue(h.base, 1);
    assert.equal((await h.admin("POST", `/approvals/${id}/decide`, { decision: "APPROVE" })).status, 200);
    for (const decision of ["APPROVE", "REJECT"]) {
      const again = (await h.admin("POST", `/approvals/${id}/decide`, { decision })) as Decided;
      assert.equal(again.status, 409, decision);
      assert.equal(again.data.alreadyTaken, true);
      assert.equal(again.data.status, "APPROVED");
      assert.match(String(again.data.message), /^Action already taken: #\d+ is already APPROVED/);
    }
    assert.equal(h.hits.length, 1, "executed exactly once");
  });

  test("simultaneous approve + reject: exactly one wins, the other is told it was already taken", async () => {
    const h = await makeHarness({ rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } } });
    for (let n = 0; n < 5; n++) {
      const id = await queue(h.base, 100 + n);
      const results = (await Promise.all([
        h.admin("POST", `/approvals/${id}/decide`, { decision: "APPROVE" }),
        h.admin("POST", `/approvals/${id}/decide`, { decision: "REJECT" }),
        h.admin("POST", `/approvals/${id}/decide`, { decision: "APPROVE" }),
      ])) as Decided[];
      const winners = results.filter((r) => r.status === 200);
      assert.equal(winners.length, 1, `round ${n}: one decision applies`);
      for (const loser of results.filter((r) => r.status !== 200)) {
        assert.equal(loser.status, 409);
        assert.equal(loser.data.alreadyTaken, true);
      }
    }
    // Every approve that won ran once; rejects never ran.
    const approved = await sqliteGet<{ n: number }>(h.dbPath, "SELECT COUNT(*) n FROM pending_actions WHERE status = 'APPROVED'");
    assert.equal(h.hits.length, approved?.n);
  });

  test("past the 24 h window an action is EXPIRED and cannot be decided", async () => {
    const h = await makeHarness({ rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } } });
    const id = await queue(h.base, 200);
    const row = await sqliteGet<{ expires_at: number; timestamp: string }>(h.dbPath, "SELECT expires_at, timestamp FROM pending_actions WHERE id = ?", [id]);
    assert.ok(row);
    assert.ok(Math.abs(row.expires_at - Date.parse(row.timestamp) - 24 * 60 * 60_000) < 5_000, "queued with a 24 h expiry");
    await sqliteRun(h.dbPath, "UPDATE pending_actions SET expires_at = ? WHERE id = ?", [Date.now() - 1, id]);
    const late = (await h.admin("POST", `/approvals/${id}/decide`, { decision: "APPROVE" })) as Decided;
    assert.equal(late.status, 410);
    assert.equal(late.data.alreadyTaken, true);
    assert.equal(late.data.status, "EXPIRED");
    assert.match(String(late.data.message), /^Action already taken: #\d+ expired before it was decided/);
    assert.equal(h.hits.length, 0);
  });
});

// ---------------------------------------------------------------------------
// 5. Dashboard filters: true approval counts, ID search, log filters shared with the CSV export
// ---------------------------------------------------------------------------
describe("5. dashboard filters", () => {
  test("approval counts are not capped by the list, and the list filters by status and id", async () => {
    const h = await makeHarness({ rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } }, rateLimitPerMinute: 1000 });
    const ids: number[] = [];
    for (let i = 0; i < 105; i++) {
      const r = await postJson(`${h.base}/api/refund`, { orderId: `C-${i}`, amount: 10 });
      ids.push(((await r.json()) as { approvalId: number }).approvalId);
    }
    assert.equal((await h.admin("POST", `/approvals/${ids[0]}/decide`, { decision: "REJECT" })).status, 200);

    const counts = (await h.admin("GET", "/approvals/counts")).data as { total: number; pending: number };
    assert.deepEqual(counts, { total: 105, pending: 104 });
    assert.equal(((await h.admin("GET", "/approvals")).data as unknown[]).length, 100, "default list is still capped");
    assert.equal(((await h.admin("GET", "/approvals?limit=200")).data as unknown[]).length, 105);

    const pending = (await h.admin("GET", "/approvals?status=PENDING&limit=500")).data as Array<{ status: string }>;
    assert.equal(pending.length, 104);
    assert.ok(pending.every((a) => a.status === "PENDING"));

    const one = (await h.admin("GET", `/approvals?id=%23${ids[50]}`)).data as Array<{ id: number }>;
    assert.deepEqual(one.map((a) => a.id), [ids[50]], "#736 or 736 both work");
    assert.equal(((await h.admin("GET", "/approvals?id=abc")).data as unknown[]).length, 0, "a bad id matches nothing");
  });

  test("audit logs filter by request id, exact path and user agent; the CSV export uses the same filters", async () => {
    const h = await makeHarness({
      rules: { "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" }, "/api/refund-status": { mode: "ALLOW", description: "" } },
    });
    const post = (body: unknown, ua: string) =>
      fetch(`${h.base}/api/refund`, { method: "POST", headers: { "content-type": "application/json", "user-agent": ua }, body: JSON.stringify(body) });
    const queued = await post({ orderId: "X-1", amount: 10 }, "billing-bot/2.0");
    const { approvalId } = (await queued.json()) as { approvalId: number };
    await (await post({ orderId: "X-2", amount: 10 }, "other-bot/1.0")).arrayBuffer();
    await (await fetch(`${h.base}/api/refund-status`, { headers: { "user-agent": "billing-bot/2.0" } })).arrayBuffer();

    type Row = { action_id: number | null; path: string; user_agent: string };
    const byId = (await h.admin("GET", `/logs?action_id=${approvalId}`)).data as Row[];
    assert.equal(byId.length, 1);
    assert.equal(byId[0].action_id, approvalId);

    const exact = (await h.admin("GET", "/logs?method=POST&path=/api/refund")).data as Row[];
    assert.equal(exact.length, 2, "exact path: /api/refund-status is not included");
    assert.ok(exact.every((r) => r.path === "/api/refund"));
    assert.equal(((await h.admin("GET", "/logs?search=/api/refund")).data as Row[]).length, 3, "search is still a substring match");

    const byAgent = (await h.admin("GET", "/logs?user_agent=billing-bot/2.0")).data as Row[];
    assert.equal(byAgent.length, 2);
    assert.ok(byAgent.every((r) => r.user_agent === "billing-bot/2.0"));

    const csv = await fetch(`${h.base}/api/agent-admin/logs/export.csv?user_agent=billing-bot/2.0&path=/api/refund`, {
      headers: { "x-admin-token": "v12-suite-admin-token-0123456789abcdef" },
    });
    assert.equal(csv.status, 200);
    const lines = (await csv.text()).trim().split("\n");
    assert.equal(lines.length, 2, "header + the one matching row");
    assert.ok(lines[1].includes("billing-bot/2.0") && lines[1].includes("/api/refund"));
  });
});
