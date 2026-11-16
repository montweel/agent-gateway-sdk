/**
 * Credentials are write-only through the admin API: Telegram / Slack / custom + rollback webhook
 * secrets and the SSO shared secret are masked in every response, survive a masked value being
 * posted back, are revealable only by admins, and never reach the auditor evidence pack.
 *
 * Run: npm test
 */
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import { createRedactor, scrubSecrets } from "../src/core/redactor";
import { ADMIN_TOKEN, makeHarness, runCleanups, tempDir, onCleanup } from "./helpers";

after(runCleanups);

const VIEWER_TOKEN = "v24-viewer-token-0123456789abcdef0123";
const TELEGRAM = "123456789:AAH_telegram_secret_token_abcdefghij";
const SLACK_URL = "https://hooks.slack.com/services/T0000/B0000/slacksecretXYZ123";
const SLACK_BOT = "xoxb-1234-5678-abcdefghsecret";
const SLACK_APP = "xapp-1-A0123-4567-appsecretzz";
const WEBHOOK_URL = "https://hooks.example.com/mont?token=urlsecret987";
const WEBHOOK_SECRET = "whsecret-abcdef123456";
const ROLLBACK_SECRET = "rbsecret-abcdef123456";
const SSO_SECRET = "s".repeat(32) + "ssoTail";
const RAW = [TELEGRAM, SLACK_URL, "slacksecretXYZ123", SLACK_BOT, SLACK_APP, WEBHOOK_SECRET, ROLLBACK_SECRET, SSO_SECRET];

function assertNoRaw(text: string, values: string[], where: string) {
  for (const v of values) assert.ok(!text.includes(v), `${where} must not contain ${v.slice(0, 12)}…`);
}

async function harness() {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "config.json"),
    JSON.stringify({ targetUrl: "", rateLimitPerMinute: 1000, ssoTrustProxyHeader: true, ssoSharedSecret: SSO_SECRET })
  );
  onCleanup(async () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  const h = await makeHarness({
    dir,
    rules: { "POST /api/pay": { mode: "ALLOW", description: `notify ${SLACK_URL} via bot${TELEGRAM}` } },
    gatewayOptions: { viewerToken: VIEWER_TOKEN },
  });
  // Channels stay disabled: nothing is sent anywhere during the test.
  const saved = await h.admin("POST", "/setup", {
    notifications: {
      telegram: { enabled: false, mode: "polling", botToken: TELEGRAM, chatId: "-100111" },
      slack: { enabled: false, mode: "socket", webhookUrl: SLACK_URL, botToken: SLACK_BOT, appToken: SLACK_APP, channelId: "C0123ABCD" },
      webhook: { enabled: false, url: WEBHOOK_URL, secret: WEBHOOK_SECRET },
    },
    rollback: { url: "https://rollback.example.com/undo", secret: ROLLBACK_SECRET },
  });
  assert.equal(saved.status, 200);
  assertNoRaw(JSON.stringify(saved.data), RAW, "POST /setup response");
  return h;
}

const viewer = { "x-admin-token": VIEWER_TOKEN };

describe("credential masking", () => {
  test("GET /setup and GET /config mask every credential, for admins too; viewers also lose webhook URLs", async () => {
    const h = await harness();

    const admin = await h.admin("GET", "/setup");
    assertNoRaw(JSON.stringify(admin.data), RAW, "admin GET /setup");
    const n = admin.data.settings.notifications;
    assert.equal(n.telegram.botToken, "••••••••ghij", "the last 4 characters identify which token is set");
    assert.match(n.slack.webhookUrl, /^••••••••/);
    assert.equal(n.webhook.url, WEBHOOK_URL, "admins keep the custom webhook URL to edit it");

    const v = await h.admin("GET", "/setup", undefined, viewer);
    assert.equal(v.status, 200);
    assertNoRaw(JSON.stringify(v.data), [...RAW, "urlsecret987", "/undo"], "viewer GET /setup");
    assert.equal(v.data.settings.notifications.webhook.url, "https://hooks.example.com/••••••••");

    const cfg = await h.admin("GET", "/config");
    assertNoRaw(JSON.stringify(cfg.data), RAW, "admin GET /config");
    assert.equal(cfg.data.ssoSharedSecret, "••••••••Tail");
    assert.equal(cfg.data.ssoSharedSecretConfigured, true);
    const vcfg = await h.admin("GET", "/config", undefined, viewer);
    assert.ok(!("ssoSharedSecret" in vcfg.data), "viewers do not get the SSO secret at all");
  });

  test("posting masked values back (partial saves) keeps every stored secret", async () => {
    const h = await harness();
    const current = (await h.admin("GET", "/setup")).data.settings;

    // The dashboard re-posts the whole notification form with the masks, changing only the chat id.
    const notifications = structuredClone(current.notifications);
    notifications.telegram.chatId = "-100222";
    const r = await h.admin("POST", "/setup", { notifications, rollback: current.rollback });
    assert.equal(r.status, 200);
    assert.equal(r.data.settings.notifications.telegram.chatId, "-100222");
    // Unrelated sections and /config saves leave them alone too.
    assert.equal((await h.admin("POST", "/setup", { privacy: { redactEmails: false } })).status, 200);
    const c = await h.admin("POST", "/config", { rateLimitPerMinute: 500, ssoSharedSecret: "••••••••Tail" });
    assert.equal(c.status, 200);
    assertNoRaw(JSON.stringify(c.data), RAW, "POST /config response");

    const reveal = async (field: string) => (await h.admin("GET", `/secrets/${field}`)).data.value;
    assert.equal(await reveal("telegram.botToken"), TELEGRAM);
    assert.equal(await reveal("slack.webhookUrl"), SLACK_URL);
    assert.equal(await reveal("slack.botToken"), SLACK_BOT);
    assert.equal(await reveal("slack.appToken"), SLACK_APP);
    assert.equal(await reveal("webhook.secret"), WEBHOOK_SECRET);
    assert.equal(await reveal("rollback.secret"), ROLLBACK_SECRET);
    assert.equal(await reveal("sso.sharedSecret"), SSO_SECRET);
    assert.equal(JSON.parse(fs.readFileSync(path.join(h.dir, "config.json"), "utf8")).ssoSharedSecret, SSO_SECRET);

    // A real new value still replaces the old one, and "" clears it.
    const next = "987654321:BBH_new_telegram_token_abcdefghijk";
    await h.admin("POST", "/setup", { notifications: { telegram: { botToken: next } } });
    assert.equal(await reveal("telegram.botToken"), next);
    await h.admin("POST", "/setup", { notifications: { telegram: { botToken: "" } } });
    assert.equal(await reveal("telegram.botToken"), "");
  });

  test("GET /secrets/:field is admin-only and allow-listed", async () => {
    const h = await harness();
    const v = await h.admin("GET", "/secrets/telegram.botToken", undefined, viewer);
    assert.equal(v.status, 403);
    assertNoRaw(JSON.stringify(v.data), RAW, "viewer reveal");
    assert.equal((await h.admin("GET", "/secrets/sso.sharedSecret", undefined, viewer)).status, 403);
    assert.equal((await h.admin("GET", "/secrets/__proto__")).status, 404);
    assert.equal((await h.admin("GET", "/secrets/replayEncryptionKey")).status, 404);
    const res = await fetch(`${h.base}/api/agent-admin/secrets/telegram.botToken`, { headers: { "x-admin-token": ADMIN_TOKEN } });
    assert.equal(res.headers.get("cache-control"), "no-store");
  });

  test("the auditor evidence pack (JSON and report) carries no credential", async () => {
    const h = await harness();
    const json = await (await fetch(`${h.base}/api/agent-admin/audit/export-pack?format=json`, { headers: { "x-admin-token": ADMIN_TOKEN } })).text();
    const md = await (await fetch(`${h.base}/api/agent-admin/audit/export-pack?format=report`, { headers: { "x-admin-token": ADMIN_TOKEN } })).text();
    for (const [name, text] of [["json", json], ["report", md]] as const) {
      assertNoRaw(text, [...RAW, "urlsecret987", "rollback.example.com"], `evidence pack (${name})`);
    }
    const bundle = JSON.parse(json);
    // The rule description that embedded a Slack URL and a Telegram token was scrubbed, not dropped.
    assert.match(bundle.policySnapshot.workspaces[0].rules["POST /api/pay"].description, /^notify \[REDACTED:secret\] via \[REDACTED:secret\]$/);
    assert.ok(!JSON.stringify(bundle.policySnapshot).includes("notifications"));
  });
});

describe("redactor patterns", () => {
  test("Telegram tokens (bare and inside /bot<token>/ URLs) and Slack webhook URLs", () => {
    const r = createRedactor(() => ({ redactEmails: true, redactPhones: true }));
    assert.equal(r.text(`GET https://api.telegram.org/bot${TELEGRAM}/sendMessage`), "GET https://api.telegram.org/[REDACTED:secret]/sendMessage");
    assert.equal(r.text(`token=${TELEGRAM}`), "token=[REDACTED:secret]");
    assert.equal(r.text(`post to ${SLACK_URL} now`), "post to [REDACTED:secret] now");
    assert.equal(r.text("https://hooks.slack.com/workflows/T1/A2/abc/def"), "[REDACTED:secret]");
    assert.equal(scrubSecrets(SLACK_URL).hits, 1, "the response guard sees it as a secret too");
    const body = JSON.parse(r.jsonText(JSON.stringify({ note: `cb ${SLACK_URL}`, nested: [{ url: `https://api.telegram.org/bot${TELEGRAM}/x` }] }))!);
    assertNoRaw(JSON.stringify(body), [TELEGRAM, "slacksecretXYZ123"], "redacted JSON");
    // No false positive on ordinary text with a colon.
    assert.equal(r.text("order 12345678: shipped"), "order 12345678: shipped");
  });
});
