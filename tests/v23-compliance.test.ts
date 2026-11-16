/**
 * v2.3 compliance: industry templates and the Auditor Evidence Pack.
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { mdEscape } from "../src/core/evidencePack";
import { ADMIN_TOKEN, makeHarness, postJson, runCleanups, sleep, sqliteGet, sqliteRun, waitFor } from "./helpers";

after(runCleanups);

async function download(base: string, query: string, headers: Record<string, string> = {}) {
  const res = await fetch(`${base}/api/agent-admin/audit/export-pack?${query}`, { headers: { "x-admin-token": ADMIN_TOKEN, ...headers } });
  return { status: res.status, disposition: res.headers.get("content-disposition") ?? "", type: res.headers.get("content-type") ?? "", text: await res.text() };
}

describe("industry compliance templates", () => {
  test("apply: redact keys merged (custom keys kept), frameworks recorded, validation", async () => {
    const h = await makeHarness({ rules: { "POST /api/pay": { mode: "ALLOW", description: "" } } });
    assert.equal((await h.admin("POST", "/config", { audit: { redactKeys: ["customer_ref", "IBAN"] } })).status, 200);

    const list = (await h.admin("GET", "/compliance/templates")).data;
    assert.deepEqual(
      list.templates.map((t: { id: string }) => t.id),
      ["fintech", "retail", "travel", "custom"]
    );
    assert.equal(list.activeTemplate, null);

    assert.equal((await h.admin("POST", "/compliance/apply-template", { template: "nope" })).status, 400);
    assert.equal((await h.admin("POST", "/compliance/apply-template", { template: "fintech", includeRules: "yes" })).status, 400);
    assert.equal((await h.admin("POST", "/compliance/apply-template", { template: "fintech", frameworks: ["<script>"] })).status, 400);

    const applied = await h.admin("POST", "/compliance/apply-template", { template: "fintech" });
    assert.equal(applied.status, 200);
    const audit = applied.data.config.audit;
    assert.deepEqual(audit.redactKeys.slice(0, 2), ["customer_ref", "IBAN"], "existing keys kept, in order");
    assert.ok(audit.redactKeys.includes("routing_number"));
    assert.equal(audit.redactKeys.filter((k: string) => k.toLowerCase() === "iban").length, 1, "no case-insensitive duplicates");
    assert.ok(!applied.data.addedRedactKeys.includes("iban"));
    assert.equal(audit.activeTemplate, "fintech");
    assert.deepEqual(audit.complianceFrameworks, ["PCI-DSS", "SOC2"]);
    assert.equal(applied.data.rules, null, "rules only when asked");

    // The merged keys take effect on stored payloads (the redact-key set refreshes within a second).
    await sleep(1100);
    assert.equal((await postJson(`${h.base}/api/pay`, { routing_number: "021000021", note: "ok" })).status, 200);
    const row = await waitFor(async () => sqliteGet<{ request_snapshot: string }>(h.dbPath, "SELECT request_snapshot FROM agent_logs WHERE status = 'ALLOWED'"), 5000, "row");
    assert.ok(!row.request_snapshot.includes("021000021"));

    // Custom: user frameworks + keys; switching templates keeps everything already there.
    const custom = await h.admin("POST", "/compliance/apply-template", { template: "custom", frameworks: ["SOC2", "HIPAA", "soc2"], redactKeys: ["mrn"] });
    assert.equal(custom.status, 200);
    assert.deepEqual(custom.data.config.audit.complianceFrameworks, ["SOC2", "HIPAA"]);
    assert.ok(custom.data.config.audit.redactKeys.includes("mrn"));
    assert.ok(custom.data.config.audit.redactKeys.includes("routing_number"), "earlier template keys are not removed");
    // Saving the audit card later (capturePayloads / redactKeys only) keeps the template and frameworks.
    const saved = await h.admin("POST", "/config", { audit: { capturePayloads: false } });
    assert.equal(saved.data.config.audit.activeTemplate, "custom");
    assert.deepEqual(saved.data.config.audit.complianceFrameworks, ["SOC2", "HIPAA"]);
  });

  test("includeRules adds approval rules but never overrides a decision already made", async () => {
    const h = await makeHarness({
      rules: {
        "/api/*refund*": { mode: "BLOCK", description: "we never refund via agents" },
        "/api/*payout*": { mode: "ALLOW", description: "too loose" },
        "POST /api/*transfer*": { mode: "ALLOW", description: "my own transfer rule" },
      },
    });
    const r = await h.admin("POST", "/compliance/apply-template", { template: "fintech", includeRules: true });
    assert.equal(r.status, 200);
    const { added, skipped } = r.data.rules as { added: string[]; skipped: Array<{ key: string; reason: string }> };
    assert.deepEqual(added.sort(), ["DELETE /api/*", "POST /api/*payout*"]);
    const reasons = Object.fromEntries(skipped.map((s) => [s.key, s.reason]));
    assert.match(reasons["POST /api/*transfer*"], /already exists/);
    assert.match(reasons["POST /api/*refund*"], /already blocks it/);

    // Payouts tightened from ALLOW to approval; refunds stay blocked; transfers keep the user's rule.
    assert.equal((await postJson(`${h.base}/api/payout`, { amount: 5 })).status, 202);
    assert.equal((await postJson(`${h.base}/api/refund`, { amount: 5 })).status, 403);
    assert.equal((await postJson(`${h.base}/api/transfer`, { amount: 5 })).status, 200);
    assert.equal((await fetch(`${h.base}/api/customers/1`, { method: "DELETE" })).status, 202, "default-denied deletes become approvable");

    const again = await h.admin("POST", "/compliance/apply-template", { template: "fintech", includeRules: true });
    assert.deepEqual(again.data.rules.added, [], "applying twice is a no-op");
  });
});

describe("auditor evidence pack", () => {
  test("JSON bundle: filters, ledger status, summary, checksum that detects edits", async () => {
    const h = await makeHarness({
      rules: { "POST /api/pay": { mode: "ALLOW", description: "" }, "POST /api/refund": { mode: "REQUIRE_APPROVAL", description: "" } },
    });
    const key = (await h.admin("POST", "/agent-keys", { name: "billing-bot" })).data.key as string;
    await postJson(`${h.base}/api/pay`, { amount: 1, password: "pw-1" }, { "x-agent-key": key, "x-forwarded-user": "alice" });
    await postJson(`${h.base}/api/pay`, { amount: 2 }, { "x-forwarded-user": "bob" });
    const q = (await (await postJson(`${h.base}/api/refund`, { amount: 9 }, { "x-agent-key": key, "x-forwarded-user": "alice" })).json()) as { approvalId: number };
    await h.admin("POST", `/approvals/${q.approvalId}/decide`, { decision: "APPROVE" });
    await postJson(`${h.base}/api/nope`, {});

    assert.equal((await download(h.base, "format=pdf")).status, 400);
    assert.equal((await download(h.base, "from=yesterday-ish")).status, 400);
    assert.equal((await download(h.base, "from=2030-01-01&to=2020-01-01")).status, 400);

    const all = await download(h.base, "format=json");
    assert.equal(all.status, 200);
    assert.match(all.disposition, /attachment; filename="mont-auditor-evidence-\d{4}-\d{2}-\d{2}\.json"/);
    const bundle = JSON.parse(all.text);
    assert.deepEqual(Object.keys(bundle), ["metadata", "ledgerVerification", "policySnapshot", "summary", "logs", "bundleSha256"]);

    // Checksum: recompute exactly as metadata.checksumMethod says.
    const { bundleSha256, ...rest } = bundle;
    const sha = (o: unknown) => crypto.createHash("sha256").update(JSON.stringify(o), "utf8").digest("hex");
    assert.equal(sha(rest), bundleSha256);
    rest.logs[0].status = "ALLOWED-EDITED";
    assert.notEqual(sha(rest), bundleSha256, "any edit changes the checksum");

    assert.equal(bundle.ledgerVerification.status, "PASS");
    assert.equal(bundle.ledgerVerification.sealedRowsVerified, bundle.logs.length);
    assert.equal(bundle.ledgerVerification.latestRowHash, bundle.logs[bundle.logs.length - 1].rowHash);
    const s = bundle.summary;
    assert.equal(s.total, 4, "the APPROVED decision row is not a new request");
    assert.equal(s.allowed, 2);
    assert.equal(s.blocked, 1);
    assert.equal(s.heldForApproval, 1);
    assert.equal(s.approved, 1);
    assert.equal(s.endUsers.agentClaimedRows, 4);
    assert.equal(s.perAgent.find((a: { agent: string }) => a.agent === "billing-bot").total, 2);
    assert.ok(!all.text.includes("pw-1"), "payloads stay redacted");
    assert.ok(!JSON.stringify(bundle.policySnapshot).includes(key));
    assert.ok(bundle.policySnapshot.workspaces[0].rules["POST /api/pay"]);

    const alice = JSON.parse((await download(h.base, `format=json&endUser=alice&agentName=billing-bot`)).text);
    assert.deepEqual(
      alice.logs.map((l: { status: string }) => l.status),
      ["ALLOWED", "QUEUED", "APPROVED"]
    );
    assert.equal(alice.logs[2].approvedBy, "Admin (Dashboard)");
    assert.equal(alice.logs[2].decidedBy, "api-token-admin");
    assert.equal(alice.logs[2].rejectedBy, null);
    assert.equal(alice.metadata.scope.endUser, "alice");

    const future = JSON.parse((await download(h.base, `format=json&from=${encodeURIComponent(new Date(Date.now() + 3600_000).toISOString())}`)).text);
    assert.equal(future.logs.length, 0);
    assert.equal(future.ledgerVerification.status, "PASS", "the certificate always covers the whole ledger");

    // Tampering shows up in the pack.
    await sqliteRun(h.dbPath, "UPDATE agent_logs SET status = 'ALLOWED' WHERE status = 'BLOCKED'");
    const tampered = JSON.parse((await download(h.base, "format=json")).text);
    assert.equal(tampered.ledgerVerification.status, "FAIL");
    assert.ok(tampered.ledgerVerification.brokenAtRowId);
  });

  test("Markdown report: five sections, agent-controlled text cannot inject links or HTML", async () => {
    const h = await makeHarness({ rules: { "POST /api/pay": { mode: "ALLOW", description: "" } } });
    await h.admin("POST", "/compliance/apply-template", { template: "retail" });
    await postJson(`${h.base}/api/pay`, { amount: 1 }, { "x-forwarded-user": "[click](http://evil.example)<img>" });
    const r = await download(h.base, "format=report");
    assert.equal(r.status, 200);
    assert.match(r.type, /text\/markdown/);
    assert.match(r.disposition, /mont-auditor-report-\d{4}-\d{2}-\d{2}\.md/);
    for (const heading of [
      "# AI Agent Compliance & Audit Attestation Report",
      "## 1. Audit scope",
      "## 2. Cryptographic ledger integrity certificate",
      "## 3. Governance & redaction policy snapshot",
      "## 4. Summary metrics",
      "## 5. Scoped transaction log",
    ]) {
      assert.ok(r.text.includes(heading), heading);
    }
    assert.match(r.text, /\*\*Result: PASS\.\*\*/);
    assert.match(r.text, /Retail & E-Commerce/);
    assert.match(r.text, /GDPR, CCPA/);
    assert.ok(r.text.includes("billing\\_address"), "template keys listed (Markdown-escaped)");
    assert.ok(!r.text.includes("[click](http://evil.example)"), "link syntax escaped");
    assert.ok(!r.text.includes("<img>"), "HTML escaped");
    assert.match(r.text, /\(agent-claimed\)/);
    assert.equal(mdEscape("a|b\nc"), "a\\|b c");
  });

  test("the pack is Pro gated; templates are not", async () => {
    const h = await makeHarness({ license: null });
    await h.admin("POST", "/license/simulate-trial-expiry?state=expired");
    const r = await download(h.base, "format=json");
    assert.equal(r.status, 402);
    assert.equal(JSON.parse(r.text).proRequired, true);
    assert.equal((await h.admin("GET", "/compliance/templates")).status, 200, "templates are not gated");
  });
});
