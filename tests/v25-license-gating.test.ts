/**
 * v2.5 license tier alignment (matches montweel.com/#pricing):
 *
 *   Community (free, no key)  core proxy, rate limiting, payload redaction, compliance presets,
 *                             end-user / approver attribution, local approvals: zero friction
 *   Pro                       Auditor Evidence Pack, ledger verification, Prometheus metrics,
 *                             team accounts, >2 agent keys, extra workspaces... -> 402 without a key
 *   Agency                    All-Clients Overview, per-client Telegram / Slack routing -> 402 on Pro
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { testLicense } from "./testLicense";
import { ADMIN_TOKEN, makeHarness, postJson, runCleanups, sleep, sqliteGet, waitFor } from "./helpers";

after(runCleanups);

/** A gateway on the free Community tier: no key, and the 7-day instant trial already over. */
async function communityHarness(opts: Parameters<typeof makeHarness>[0] = {}) {
  const h = await makeHarness({ ...opts, license: null });
  const st = await h.admin("POST", "/license/simulate-trial-expiry?state=expired");
  assert.equal(st.data.tier, "COMMUNITY");
  return h;
}

async function raw(base: string, p: string) {
  const res = await fetch(`${base}/api/agent-admin${p}`, { headers: { "x-admin-token": ADMIN_TOKEN } });
  return { status: res.status, text: await res.text() };
}

describe("Community tier: core features are open without a license key", () => {
  test("proxy decisions, rate limiting, redaction, compliance presets, attribution and local approvals all work", async () => {
    const h = await communityHarness({
      rateLimitPerMinute: 1000,
      rules: {
        "POST /api/pay": { mode: "ALLOW", description: "" },
        "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" },
        "DELETE /api/*": { mode: "BLOCK", description: "" },
      },
    });

    // Core proxy: allow / block / hold.
    assert.equal((await postJson(`${h.base}/api/pay`, { amount: 1 })).status, 200);
    assert.equal((await fetch(`${h.base}/api/customers/1`, { method: "DELETE" })).status, 403);

    // Industry compliance presets + PII redaction.
    assert.equal((await h.admin("GET", "/compliance/templates")).status, 200);
    const applied = await h.admin("POST", "/compliance/apply-template", { template: "fintech" });
    assert.equal(applied.status, 200, "compliance presets are Community");
    assert.ok(applied.data.config.audit.redactKeys.includes("routing_number"));
    await sleep(1100); // redact-key set refreshes within a second
    assert.equal((await postJson(`${h.base}/api/pay`, { routing_number: "021000021" }, { "x-forwarded-user": "alice" })).status, 200);
    const row = await waitFor(
      async () => sqliteGet<{ request_snapshot: string }>(h.dbPath, "SELECT request_snapshot FROM agent_logs WHERE request_snapshot LIKE '%routing_number%'"),
      5000,
      "redacted row"
    );
    assert.ok(!row.request_snapshot.includes("021000021"), "PII is redacted on Community");

    // Local approvals + approver attribution.
    const held = (await (await postJson(`${h.base}/api/refund`, { amount: 9 }, { "x-forwarded-user": "bob" })).json()) as { approvalId: number };
    const decided = await h.admin("POST", `/approvals/${held.approvalId}/decide`, { decision: "APPROVE" });
    assert.equal(decided.status, 200, "local dashboard approvals are Community");

    // The 2 free agent keys.
    assert.equal((await h.admin("POST", "/agent-keys", { name: "bot-1" })).status, 201);
    assert.equal((await h.admin("POST", "/agent-keys", { name: "bot-2" })).status, 201);
  });

  test("rate limiting is enforced on Community", async () => {
    const h = await communityHarness({ rateLimitPerMinute: 3, rules: { "POST /api/pay": { mode: "ALLOW", description: "" } } });
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await postJson(`${h.base}/api/pay`, { i })).status);
    assert.ok(statuses.includes(200));
    assert.ok(statuses.includes(429), `expected a 429 in ${statuses.join(",")}`);
  });
});

describe("Pro gates: 402 Payment Required on Community, open with a valid Pro key", () => {
  test("GET /audit/export-pack is 402 on Community and 200 once a Pro key is active", async () => {
    const h = await communityHarness({ rules: { "POST /api/pay": { mode: "ALLOW", description: "" } } });
    await postJson(`${h.base}/api/pay`, { amount: 1 });

    const denied = await raw(h.base, "/audit/export-pack?format=json");
    assert.equal(denied.status, 402);
    const body = JSON.parse(denied.text);
    assert.equal(body.proRequired, true);
    assert.equal(body.error, "Payment Required");
    assert.equal(body.feature, "auditVerification");

    // Every other paid endpoint answers 402 too (never 200 with an upgrade flag).
    assert.equal((await raw(h.base, "/audit/verify")).status, 402);
    assert.equal((await raw(h.base, "/metrics")).status, 402);
    assert.equal((await h.admin("POST", "/users", { username: "auditor", role: "viewer" })).status, 402);
    await h.admin("POST", "/agent-keys", { name: "bot-1" });
    await h.admin("POST", "/agent-keys", { name: "bot-2" });
    const third = await h.admin("POST", "/agent-keys", { name: "bot-3" });
    assert.equal(third.status, 402, "a 3rd agent key needs Pro");
    assert.equal(third.data.proRequired, true);
    assert.equal((await h.admin("POST", "/workspaces", { name: "Acme" })).status, 402);

    // Activate a valid Pro key: unlocked instantly, no restart.
    const act = await h.admin("POST", "/license", { licenseKey: testLicense("PRO") });
    assert.equal(act.status, 200);
    assert.equal(act.data.tier, "PRO");

    const ok = await raw(h.base, "/audit/export-pack?format=json");
    assert.equal(ok.status, 200);
    assert.ok(JSON.parse(ok.text).bundleSha256);
    assert.equal((await raw(h.base, "/audit/export-pack?format=report")).status, 200);
    assert.equal((await raw(h.base, "/audit/verify")).status, 200);
    const metrics = await raw(h.base, "/metrics");
    assert.equal(metrics.status, 200);
    assert.match(metrics.text, /agent_gateway_requests_total/);
    assert.equal((await h.admin("POST", "/users", { username: "auditor", role: "viewer" })).status, 201);
    assert.equal((await h.admin("POST", "/agent-keys", { name: "bot-3" })).status, 201);

    // Removing the key relocks it.
    await h.admin("DELETE", "/license");
    assert.equal((await raw(h.base, "/audit/export-pack?format=json")).status, 402);
  });

  test("an invalid or forged key never unlocks a Pro endpoint", async () => {
    const h = await communityHarness();
    assert.equal((await h.admin("POST", "/license", { licenseKey: "MONT-V2.abc.def" })).status, 400);
    assert.equal((await raw(h.base, "/audit/export-pack")).status, 402);
  });
});

describe("Agency gates: 402 on Pro, open with an Agency key", () => {
  test("All-Clients Overview and per-client Telegram / Slack routing need Agency", async () => {
    // Activated from the dashboard API (a host-option key would outrank the later Agency upgrade).
    const h = await communityHarness({ rules: {} });
    assert.equal((await h.admin("POST", "/license", { licenseKey: testLicense("PRO") })).data.tier, "PRO");

    const overview = await h.admin("GET", "/workspaces/overview");
    assert.equal(overview.status, 402);
    assert.equal(overview.data.proRequired, true);
    assert.equal(overview.data.agencyRequired, true);
    assert.equal(overview.data.feature, "allClientsOverview");

    // Pro still gets its 3 workspaces, just without per-client chat routing.
    const routed = await h.admin("POST", "/workspaces", { name: "Acme", telegramChatId: "-1001234567890" });
    assert.equal(routed.status, 402);
    assert.equal(routed.data.agencyRequired, true);
    const plain = await h.admin("POST", "/workspaces", { name: "Acme" });
    assert.equal(plain.status, 201, "Pro covers extra workspaces");
    assert.equal((await h.admin("PATCH", "/workspaces/acme", { slackChannel: "C0123ABCD" })).status, 402);
    assert.equal((await h.admin("PATCH", "/workspaces/acme", { name: "Acme Co", slackChannel: null })).status, 200, "clearing routing is always allowed");

    const list = (await h.admin("GET", "/workspaces")).data;
    assert.equal(list.license.perClientRouting, false);
    assert.equal(list.license.allClientsOverview, false);

    // Upgrade to Agency: both unlock.
    assert.equal((await h.admin("POST", "/license", { licenseKey: testLicense("AGENCY") })).data.tier, "AGENCY");
    assert.equal((await h.admin("GET", "/workspaces/overview")).status, 200);
    assert.equal((await h.admin("PATCH", "/workspaces/acme", { slackChannel: "C0123ABCD" })).status, 200);
    assert.equal((await h.admin("GET", "/workspaces")).data.license.perClientRouting, true);
  });
});
