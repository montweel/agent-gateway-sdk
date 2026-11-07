import crypto from "crypto";
import type { GatewaySettings, PendingRow } from "./types";
import type { SettingsStore } from "./settingsStore";
import type { Redactor } from "./redactor";
import type { GatewayContext } from "./context";
import { DEFAULT_WORKSPACE_ID, MAX_NOTIFY_PAYLOAD_CHARS, NOTIFY_TIMEOUT_MS, PENDING_TTL_MS } from "./constants";
import { buildApprovalLink, parseButtonToken, signButtonToken, verifyButtonToken } from "./approvalSigning";
import type { CallbackDecision } from "./approvalSigning";
import { findHighRiskFields } from "./utils";
import { buildSummary, modeLabel, summaryLines } from "./protection";
import type { LicenseFeatures } from "./license";
import type { Workspace } from "./workspaces";

/**
 * Mobile approval bridge. Zero dependencies: native fetch and the built-in WebSocket client.
 *
 * Channels and how a decision gets back to the gateway:
 *   Telegram, mode "polling"  inline buttons with signed callback_data; this process long-polls
 *                             getUpdates OUTBOUND. No public URL, no tunnel, no open port.
 *   Telegram, mode "links"    URL buttons -> signed confirmation page (needs a Public URL).
 *   Slack, mode "socket"      bot message with buttons; taps arrive over an OUTBOUND Socket Mode
 *                             WebSocket. No public URL, no tunnel, no open port.
 *   Slack, mode "webhook"     incoming webhook with URL buttons -> confirmation page (needs a Public URL).
 *   Custom webhook            signed JSON with approveUrl / rejectUrl (when a Public URL is set).
 *
 * Every button is bound to one queued row with an HMAC (approvalSigning.ts). Taps are accepted only
 * from the configured chat / channel and, if configured, only from listed approver ids. Everything
 * sent out is scrubbed by the redactor first.
 */

export interface PendingNotice {
  id: number;
  /** pending_actions.timestamp, bound into the link / button signature. */
  queuedAt: string;
  expiresAt: number;
  method: string;
  path: string;
  /** Redacted JSON body text (or null). */
  body: string | null;
  query: Record<string, unknown>;
  callerIp: string | null;
  callerUa: string | null;
  agentKey: string | null;
  agentKeyPrefix: string | null;
  agentReason: string | null;
  matchedPolicy: string | null;
  /** Client workspace (v2): labels the message and routes it to the workspace's own chat / channel. */
  workspace?: NoticeWorkspace | null;
}

export interface NoticeWorkspace {
  id: number;
  name: string;
  slug: string;
  isDefault: boolean;
  telegramChatId: string | null;
  slackChannel: string | null;
}

export function workspaceNotice(ws: Workspace | undefined | null): NoticeWorkspace | null {
  if (!ws) return null;
  return { id: ws.id, name: ws.name, slug: ws.slug, isDefault: ws.isDefault, telegramChatId: ws.telegramChatId, slackChannel: ws.slackChannel };
}

/** "[Acme Outfitters] " for client workspaces, "" for the default one. */
function wsLabel(n: PendingNotice): string {
  return n.workspace && !n.workspace.isDefault ? `[${n.workspace.name}] ` : "";
}

export interface ChannelResult {
  channel: "slack" | "telegram" | "webhook";
  ok: boolean;
  status?: number;
  error?: string;
}

export interface Notifier {
  /** Fire-and-forget safe: never throws, never rejects. */
  notifyPending(notice: PendingNotice): Promise<ChannelResult[]>;
  /** Sends a sample notice to every enabled channel (used by the Setup tab). */
  sendTest(): Promise<ChannelResult[]>;
  /** Plain alert (security alerts, digest, emergency mode) to every enabled channel. Never rejects. */
  sendAlert(title: string, lines: string[]): Promise<ChannelResult[]>;
}

export interface BridgeEndpoints {
  telegramApiBase: string;
  slackApiBase: string;
  /** Long-poll timeout for getUpdates, seconds (0 = short polling). */
  telegramPollTimeoutSec: number;
}

export const TEST_BUTTON_TOKEN = "mont:test";

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
function prettyBody(body: string | null): string {
  if (!body) return "(no body)";
  let text: string;
  try {
    text = JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    text = body;
  }
  return text.length > MAX_NOTIFY_PAYLOAD_CHARS ? `${text.slice(0, MAX_NOTIFY_PAYLOAD_CHARS)}\n… [truncated]` : text;
}

function riskLines(body: string | null): string[] {
  if (!body) return [];
  try {
    return findHighRiskFields(JSON.parse(body)).map((f) => `${f.path} = ${JSON.stringify(f.value)}`);
  } catch {
    return [];
  }
}

function callerLine(n: PendingNotice): string {
  const parts: string[] = [];
  if (n.agentKey) parts.push(`key "${n.agentKey}"${n.agentKeyPrefix ? ` (${n.agentKeyPrefix}…)` : ""}`);
  if (n.callerIp) parts.push(`IP ${n.callerIp}`);
  if (n.callerUa) parts.push(`UA ${n.callerUa.slice(0, 80)}`);
  return parts.join(" · ") || "unknown caller";
}

function links(settings: GatewaySettings, secret: string, n: PendingNotice): { approve: string; reject: string } | null {
  if (!settings.publicBaseUrl) return null;
  const exp = Math.min(n.expiresAt, Date.now() + PENDING_TTL_MS);
  return {
    approve: buildApprovalLink(settings.publicBaseUrl, secret, { id: n.id, decision: "APPROVE", exp, queuedAt: n.queuedAt }),
    reject: buildApprovalLink(settings.publicBaseUrl, secret, { id: n.id, decision: "REJECT", exp, queuedAt: n.queuedAt }),
  };
}

function buttonTokens(secret: string, n: PendingNotice): { approve: string; reject: string } {
  if (n.id === 0) return { approve: TEST_BUTTON_TOKEN, reject: TEST_BUTTON_TOKEN };
  return { approve: signButtonToken(secret, n.id, "APPROVE", n.queuedAt), reject: signButtonToken(secret, n.id, "REJECT", n.queuedAt) };
}

const escSlack = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const escHtml = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Body signature for receivers: hex HMAC-SHA256 over "<timestamp>.<raw body>". */
export function signWebhookBody(secret: string, timestamp: string, body: string): string {
  return crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`, "utf8").digest("hex");
}

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: unknown; text: string }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(NOTIFY_TIMEOUT_MS),
  });
  const text = (await res.text().catch(() => "")).slice(0, 2000);
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

function slackOk(r: { status: number; json: unknown; text: string }): ChannelResult {
  const ok = r.status >= 200 && r.status < 300 && (r.json === null || (r.json as { ok?: unknown }).ok !== false);
  const err = (r.json as { error?: unknown } | null)?.error;
  return { channel: "slack", ok, status: r.status, ...(ok ? {} : { error: typeof err === "string" ? err : r.text.slice(0, 300) }) };
}

function slackText(n: PendingNotice): string {
  const risks = riskLines(n.body);
  return (
    `*${escSlack(n.method)}* \`${escSlack(n.path)}\`\n` +
    `*Caller:* ${escSlack(callerLine(n))}\n` +
    (n.agentReason ? `*Agent's reason:* ${escSlack(n.agentReason.slice(0, 300))}\n` : "") +
    (n.matchedPolicy ? `*Matched:* ${escSlack(n.matchedPolicy)}\n` : "") +
    (risks.length ? `:warning: *High-risk fields:* ${escSlack(risks.join(", "))}` : "")
  );
}

function slackBlocks(n: PendingNotice, actions: unknown | null, footer: string | null): unknown[] {
  const blocks: unknown[] = [
    { type: "header", text: { type: "plain_text", text: n.id === 0 ? "Test notification" : `${wsLabel(n)}Approval needed: #${n.id}`.slice(0, 150), emoji: false } },
    { type: "section", text: { type: "mrkdwn", text: slackText(n) } },
    { type: "section", text: { type: "mrkdwn", text: "```" + escSlack(prettyBody(n.body)).replace(/```/g, "'''") + "```" } },
  ];
  if (actions) blocks.push(actions);
  if (footer) blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: footer }] });
  return blocks;
}

function telegramText(n: PendingNotice, footer: string | null): string {
  const risks = riskLines(n.body);
  return (
    `<b>${n.id === 0 ? "Test notification" : `${escHtml(wsLabel(n))}Approval needed: #${n.id}`}</b>\n` +
    `<b>${escHtml(n.method)}</b> <code>${escHtml(n.path)}</code>\n` +
    `<b>Caller:</b> ${escHtml(callerLine(n))}\n` +
    (n.agentReason ? `<b>Agent's reason:</b> ${escHtml(n.agentReason.slice(0, 300))}\n` : "") +
    (n.matchedPolicy ? `<b>Matched:</b> ${escHtml(n.matchedPolicy)}\n` : "") +
    (risks.length ? `⚠️ <b>High-risk fields:</b> ${escHtml(risks.join(", "))}\n` : "") +
    `<pre>${escHtml(prettyBody(n.body))}</pre>` +
    (footer ? `\n${escHtml(footer)}` : "")
  );
}

// ---------------------------------------------------------------------------
// Senders
// ---------------------------------------------------------------------------
async function sendSlackWebhook(webhookUrl: string, n: PendingNotice, l: ReturnType<typeof links>): Promise<ChannelResult> {
  const actions = l
    ? {
        type: "actions",
        elements: [
          { type: "button", text: { type: "plain_text", text: "Approve" }, style: "primary", url: l.approve },
          { type: "button", text: { type: "plain_text", text: "Reject" }, style: "danger", url: l.reject },
        ],
      }
    : null;
  const footer = l ? null : "Set a Public URL in Gateway Setup, or switch Slack to Socket Mode, to get one-tap Approve / Reject buttons.";
  const r = await postJson(webhookUrl, { text: `Approval needed: ${n.method} ${n.path} (#${n.id})`, blocks: slackBlocks(n, actions, footer) });
  return slackOk(r);
}

const PRO_BUTTONS_FOOTER = "One-tap Approve / Reject buttons over Telegram polling and Slack Socket Mode are a Mont Pro feature. Approve this request in the dashboard.";

async function sendSlackBot(
  base: string,
  s: GatewaySettings["notifications"]["slack"],
  secret: string,
  n: PendingNotice,
  interactive: boolean
): Promise<ChannelResult> {
  const t = buttonTokens(secret, n);
  const actions = interactive
    ? {
        type: "actions",
        block_id: `mont_${n.id}`,
        elements: [
          { type: "button", action_id: "mont_approve", text: { type: "plain_text", text: "Approve" }, style: "primary", value: t.approve },
          { type: "button", action_id: "mont_reject", text: { type: "plain_text", text: "Reject" }, style: "danger", value: t.reject },
        ],
      }
    : null;
  const r = await postJson(
    `${base}/chat.postMessage`,
    {
      channel: n.workspace?.slackChannel || s.channelId,
      text: `${wsLabel(n)}Approval needed: ${n.method} ${n.path} (#${n.id})`,
      blocks: slackBlocks(n, actions, interactive ? null : PRO_BUTTONS_FOOTER),
      unfurl_links: false,
    },
    { authorization: `Bearer ${s.botToken}` }
  );
  return slackOk(r);
}

async function sendTelegram(
  base: string,
  s: GatewaySettings["notifications"]["telegram"],
  secret: string,
  n: PendingNotice,
  l: ReturnType<typeof links>,
  interactive = true
): Promise<ChannelResult> {
  const payload: Record<string, unknown> = { chat_id: n.workspace?.telegramChatId || s.chatId, parse_mode: "HTML", disable_web_page_preview: true };
  if (s.mode === "polling" && !interactive) {
    // Community: the message still arrives; buttons fall back to signed links when a Public URL exists.
    payload.text = telegramText(n, l ? null : PRO_BUTTONS_FOOTER);
    if (l) payload.reply_markup = { inline_keyboard: [[{ text: "✅ Approve", url: l.approve }, { text: "⛔ Reject", url: l.reject }]] };
  } else if (s.mode === "polling") {
    const t = buttonTokens(secret, n);
    payload.text = telegramText(n, null);
    payload.reply_markup = { inline_keyboard: [[{ text: "✅ Approve", callback_data: t.approve }, { text: "⛔ Reject", callback_data: t.reject }]] };
  } else if (l) {
    payload.text = telegramText(n, null);
    payload.reply_markup = { inline_keyboard: [[{ text: "✅ Approve", url: l.approve }, { text: "⛔ Reject", url: l.reject }]] };
  } else {
    payload.text = telegramText(n, "Set a Public URL in Gateway Setup, or switch Telegram to polling mode, to get one-tap buttons.");
  }
  const r = await postJson(`${base}/bot${encodeURIComponent(s.botToken)}/sendMessage`, payload);
  const ok = r.status >= 200 && r.status < 300;
  // Never echo the bot token in an error.
  return { channel: "telegram", ok, status: r.status, ...(ok ? {} : { error: r.text.split(s.botToken).join("[token]").slice(0, 300) }) };
}

async function sendWebhook(url: string, secret: string, n: PendingNotice, l: ReturnType<typeof links>): Promise<ChannelResult> {
  let parsedBody: unknown = null;
  try {
    parsedBody = n.body ? JSON.parse(n.body) : null;
  } catch {
    parsedBody = n.body;
  }
  const body = JSON.stringify({
    event: "approval.pending",
    action: {
      id: n.id,
      queuedAt: n.queuedAt,
      expiresAt: new Date(n.expiresAt).toISOString(),
      method: n.method,
      path: n.path,
      body: parsedBody,
      query: n.query,
      caller: { ip: n.callerIp, userAgent: n.callerUa, agentKey: n.agentKey, agentKeyPrefix: n.agentKeyPrefix },
      agentReason: n.agentReason,
      matchedPolicy: n.matchedPolicy,
      highRiskFields: riskLines(n.body),
    },
    approveUrl: l?.approve ?? null,
    rejectUrl: l?.reject ?? null,
  });
  const ts = String(Math.floor(Date.now() / 1000));
  const headers: Record<string, string> = { "x-mont-event": "approval.pending", "x-mont-timestamp": ts };
  if (secret) headers["x-mont-signature"] = `sha256=${signWebhookBody(secret, ts, body)}`;
  const r = await postJson(url, body, headers);
  const ok = r.status >= 200 && r.status < 300;
  return { channel: "webhook", ok, status: r.status, ...(ok ? {} : { error: r.text.slice(0, 300) }) };
}

// ---------------------------------------------------------------------------
// Notifier
// ---------------------------------------------------------------------------
export function createNotifier(
  settingsStore: SettingsStore,
  redactor: Redactor,
  endpoints: BridgeEndpoints,
  /** Current license features (zero-tunnel buttons are Pro / Agency). */
  features: () => LicenseFeatures
): Notifier {
  async function dispatch(raw: PendingNotice): Promise<ChannelResult[]> {
    let settings: GatewaySettings;
    let secret: string;
    try {
      settings = settingsStore.get();
      secret = settingsStore.approvalSigningSecret();
    } catch (err) {
      console.error("Notifications skipped:", err);
      return [];
    }
    // Defence in depth: callers pass already-redacted data, but nothing leaves unscrubbed.
    const n: PendingNotice = {
      ...raw,
      path: redactor.text(raw.path),
      body: redactor.jsonText(raw.body),
      query: redactor.json(raw.query) as Record<string, unknown>,
      callerUa: raw.callerUa ? redactor.text(raw.callerUa) : null,
      agentReason: raw.agentReason ? redactor.text(raw.agentReason) : null,
    };
    const l = links(settings, secret, n);
    const { slack, telegram, webhook } = settings.notifications;
    const interactive = features().interactiveApprovals;
    const jobs: Array<Promise<ChannelResult>> = [];
    const guard = (channel: ChannelResult["channel"], p: Promise<ChannelResult>): Promise<ChannelResult> =>
      p.catch((err: unknown) => ({ channel, ok: false, error: err instanceof Error ? err.message : String(err) }));

    if (slack.enabled) {
      const channel = n.workspace?.slackChannel || slack.channelId;
      if (slack.mode === "socket" && slack.botToken && channel) jobs.push(guard("slack", sendSlackBot(endpoints.slackApiBase, slack, secret, n, interactive)));
      else if (slack.mode === "webhook" && slack.webhookUrl) jobs.push(guard("slack", sendSlackWebhook(slack.webhookUrl, n, l)));
    }
    if (telegram.enabled && telegram.botToken && (n.workspace?.telegramChatId || telegram.chatId)) {
      jobs.push(guard("telegram", sendTelegram(endpoints.telegramApiBase, telegram, secret, n, l, interactive)));
    }
    if (webhook.enabled && webhook.url) jobs.push(guard("webhook", sendWebhook(webhook.url, webhook.secret, n, l)));

    const results = await Promise.all(jobs);
    for (const r of results) {
      if (!r.ok) console.error(`[agent-gateway] ${r.channel} notification failed:`, r.status ?? "", r.error ?? "");
    }
    return results;
  }

  async function alert(rawTitle: string, rawLines: string[]): Promise<ChannelResult[]> {
    let settings: GatewaySettings;
    try {
      settings = settingsStore.get();
    } catch {
      return [];
    }
    const title = redactor.text(rawTitle);
    const lines = rawLines.map((l) => redactor.text(l));
    const { slack, telegram, webhook } = settings.notifications;
    const jobs: Array<Promise<ChannelResult>> = [];
    const guard = (channel: ChannelResult["channel"], p: Promise<ChannelResult>): Promise<ChannelResult> =>
      p.catch((err: unknown) => ({ channel, ok: false, error: err instanceof Error ? err.message : String(err) }));

    if (slack.enabled) {
      const text = `*${escSlack(title)}*\n${lines.map((l) => `• ${escSlack(l)}`).join("\n")}`;
      if (slack.mode === "socket" && slack.botToken && slack.channelId) {
        jobs.push(guard("slack", postJson(`${endpoints.slackApiBase}/chat.postMessage`, { channel: slack.channelId, text }, { authorization: `Bearer ${slack.botToken}` }).then(slackOk)));
      } else if (slack.mode === "webhook" && slack.webhookUrl) {
        jobs.push(guard("slack", postJson(slack.webhookUrl, { text }).then(slackOk)));
      }
    }
    if (telegram.enabled && telegram.botToken && telegram.chatId) {
      const text = `<b>${escHtml(title)}</b>\n${lines.map((l) => `• ${escHtml(l)}`).join("\n")}`;
      jobs.push(
        guard(
          "telegram",
          postJson(`${endpoints.telegramApiBase}/bot${encodeURIComponent(telegram.botToken)}/sendMessage`, { chat_id: telegram.chatId, text, parse_mode: "HTML" }).then((r) => ({
            channel: "telegram" as const,
            ok: r.status >= 200 && r.status < 300,
            status: r.status,
          }))
        )
      );
    }
    if (webhook.enabled && webhook.url) {
      const body = JSON.stringify({ event: "alert", title, lines, at: new Date().toISOString() });
      const ts = String(Math.floor(Date.now() / 1000));
      const headers: Record<string, string> = { "x-mont-event": "alert", "x-mont-timestamp": ts };
      if (webhook.secret) headers["x-mont-signature"] = `sha256=${signWebhookBody(webhook.secret, ts, body)}`;
      jobs.push(guard("webhook", postJson(webhook.url, body, headers).then((r) => ({ channel: "webhook" as const, ok: r.status >= 200 && r.status < 300, status: r.status }))));
    }
    return Promise.all(jobs);
  }

  return {
    sendAlert: (title, lines) => alert(title, lines).catch(() => []),
    notifyPending: (n) => dispatch(n).catch(() => []),
    sendTest: () =>
      dispatch({
        id: 0,
        queuedAt: new Date().toISOString(),
        expiresAt: Date.now() + 10 * 60_000,
        method: "POST",
        path: "/api/test-notification",
        body: JSON.stringify({ amount: 250, currency: "USD", note: "This is a test from Mont Gateway setup." }),
        query: {},
        callerIp: "127.0.0.1",
        callerUa: "mont-setup-test",
        agentKey: null,
        agentKeyPrefix: null,
        agentReason: "Testing the mobile approval bridge.",
        matchedPolicy: "test",
      }),
  };
}

// ---------------------------------------------------------------------------
// Outbound approval workers (Telegram long-polling, Slack Socket Mode)
// ---------------------------------------------------------------------------
export type BridgeState = "disabled" | "connecting" | "connected" | "standby" | "error";

export interface BridgeStatus {
  state: BridgeState;
  detail: string | null;
  lastEventAt: string | null;
}

export interface ApprovalBridges {
  start(): void;
  stop(): Promise<void>;
  /** Re-read settings now (called after every settings save). */
  kick(): void;
  status(): { telegram: BridgeStatus; slack: BridgeStatus };
}

const LEASE_TTL_MS = 60_000;

/** One poller per channel across every gateway process sharing this database. */
async function holdLease(ctx: GatewayContext, channel: string): Promise<boolean> {
  const key = `bridge_lease:${channel}`;
  const now = Date.now();
  const value = JSON.stringify({ owner: ctx.instanceId, expiresAt: now + LEASE_TTL_MS });
  const r = await ctx.db.run(
    `INSERT INTO system_settings (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value
     WHERE json_extract(system_settings.value, '$.owner') = ? OR json_extract(system_settings.value, '$.expiresAt') < ?`,
    [key, value, ctx.instanceId, now]
  );
  return r.changes > 0;
}

async function releaseLease(ctx: GatewayContext, channel: string): Promise<void> {
  await ctx.db
    .run("DELETE FROM system_settings WHERE key = ? AND json_extract(value, '$.owner') = ?", [`bridge_lease:${channel}`, ctx.instanceId])
    .catch(() => undefined);
}

function approverList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

interface TgCallbackQuery {
  id: string;
  data?: string;
  from: { id: number; username?: string; first_name?: string };
  message?: { message_id: number; chat: { id: number; username?: string } };
}

interface TgMessage {
  message_id: number;
  text?: string;
  from?: { id: number; username?: string };
  chat: { id: number; username?: string };
}

/** Rebuilds a notification from a stored (already redacted) approval row. */
export function noticeFromRow(row: PendingRow, workspace?: Workspace): PendingNotice {
  let query: Record<string, unknown> = {};
  try {
    query = row.query_json ? (JSON.parse(row.query_json) as Record<string, unknown>) : {};
  } catch {
    query = {};
  }
  return {
    id: row.id,
    queuedAt: row.timestamp,
    expiresAt: row.expires_at ?? Date.now() + PENDING_TTL_MS,
    method: row.method,
    path: row.path,
    body: row.body,
    query,
    callerIp: row.caller_ip,
    callerUa: row.caller_ua,
    agentKey: row.agent_key,
    agentKeyPrefix: row.agent_key_prefix,
    agentReason: row.agent_reason,
    matchedPolicy: row.matched_policy,
    workspace: workspaceNotice(workspace),
  };
}

interface SlackBlockActions {
  type: string;
  user?: { id: string; username?: string; name?: string };
  channel?: { id: string };
  message?: { ts: string };
  actions?: Array<{ action_id?: string; value?: string }>;
}

/** Where a button tap came from. A client's approvals can only be decided from that client's chat / channel. */
type TapOrigin = { channel: "telegram"; chatMatches: (configured: string) => boolean } | { channel: "slack"; channelId: string };

function telegramChatMatcher(chat: { id: number; username?: string }): (configured: string) => boolean {
  return (configured) => {
    const c = configured.trim();
    return c !== "" && (String(chat.id) === c || (c.startsWith("@") && chat.username?.toLowerCase() === c.slice(1).toLowerCase()));
  };
}

/** Verifies a button token against its queued row and applies the decision. */
async function decideFromButton(ctx: GatewayContext, token: string, actor: string, origin: TapOrigin): Promise<{ ok: boolean; text: string }> {
  const parsed = parseButtonToken(token);
  if (!parsed) return { ok: false, text: "This button is not valid." };
  const row = await ctx.db.get<Pick<PendingRow, "id" | "timestamp" | "workspace_id">>("SELECT id, timestamp, workspace_id FROM pending_actions WHERE id = ?", [parsed.id]);
  if (!row || !verifyButtonToken(ctx.settings.approvalSigningSecret(), parsed, row.timestamp)) {
    return { ok: false, text: "This button is not valid for that request." };
  }
  // The request's workspace decides which chat / channel may approve it.
  const ws = ctx.workspaces.get(row.workspace_id ?? DEFAULT_WORKSPACE_ID);
  const n = ctx.settings.get().notifications;
  const allowed =
    origin.channel === "telegram"
      ? origin.chatMatches(ws?.telegramChatId || n.telegram.chatId)
      : origin.channelId === (ws?.slackChannel || n.slack.channelId);
  if (!allowed) {
    console.error(`[agent-gateway] Refused a ${origin.channel} button for action #${parsed.id} from a chat that does not belong to its workspace.`);
    return { ok: false, text: `#${parsed.id} belongs to another client workspace; it can only be decided from that workspace's chat or the dashboard.` };
  }
  const result = await ctx.approvals.decide(parsed.id, parsed.decision as CallbackDecision, actor);
  const body = result.body as { status?: string; message?: string; replayStatus?: number };
  if (result.status >= 200 && result.status < 300) {
    const verb = body.status === "REJECTED" ? "⛔ Rejected" : body.status === "EXECUTING" ? "✅ Approved (executing)" : "✅ Approved and executed";
    return { ok: true, text: `${verb} #${parsed.id} by ${actor}${body.replayStatus !== undefined ? ` · target replied HTTP ${body.replayStatus}` : ""}` };
  }
  return { ok: false, text: `#${parsed.id} not changed: ${body.message ?? "it could not be decided."}` };
}

export function createApprovalBridges(ctx: GatewayContext, endpoints: BridgeEndpoints): ApprovalBridges {
  let stopped = true;
  const statuses: { telegram: BridgeStatus; slack: BridgeStatus } = {
    telegram: { state: "disabled", detail: null, lastEventAt: null },
    slack: { state: "disabled", detail: null, lastEventAt: null },
  };
  let wake = new AbortController();
  const loops: Promise<void>[] = [];
  let currentSocket: WebSocket | null = null;

  const set = (ch: "telegram" | "slack", state: BridgeState, detail: string | null = null): void => {
    statuses[ch].state = state;
    statuses[ch].detail = detail;
  };

  /** Sleeps, but wakes early on kick() / stop(). */
  const nap = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const signal = wake.signal;
      // Already woken (stop()/kick() ran while we were busy): an abort listener would never fire.
      if (stopped || signal.aborted) {
        resolve();
        return;
      }
      const t = setTimeout(done, ms);
      t.unref();
      function done(): void {
        clearTimeout(t);
        signal.removeEventListener("abort", done);
        resolve();
      }
      signal.addEventListener("abort", done, { once: true });
    });

  // ---------------- Telegram ----------------
  async function tg(method: string, token: string, body: unknown): Promise<unknown> {
    const r = await postJson(`${endpoints.telegramApiBase}/bot${encodeURIComponent(token)}/${method}`, body);
    return r.json;
  }

  async function handleTelegramCallback(token: string, s: GatewaySettings["notifications"]["telegram"], cq: TgCallbackQuery): Promise<void> {
    const answer = (text: string, alert = false): Promise<unknown> =>
      tg("answerCallbackQuery", token, { callback_query_id: cq.id, text: text.slice(0, 190), show_alert: alert }).catch(() => undefined);

    const chat = cq.message?.chat;
    const matcher = chat ? telegramChatMatcher(chat) : null;
    // The global chat, or a client workspace's own chat.
    const chatMatches = matcher !== null && (matcher(s.chatId) || ctx.workspaces.list().some((w) => w.telegramChatId !== null && matcher(w.telegramChatId)));
    if (!chatMatches || !matcher) {
      console.error(`[agent-gateway] Ignored a Telegram button from an unexpected chat (${chat?.id ?? "none"}).`);
      await answer("This chat is not allowed to decide gateway approvals.", true);
      return;
    }
    const approvers = approverList(s.approverIds);
    if (approvers.length > 0 && !approvers.includes(String(cq.from.id))) {
      console.error(`[agent-gateway] Telegram user ${cq.from.id} tapped an approval button but is not an approver.`);
      await answer("You are not on the approver list for this gateway.", true);
      return;
    }
    if (cq.data === TEST_BUTTON_TOKEN) {
      await answer("Test button works. Real buttons approve or reject the request.");
      return;
    }
    await answer("Working on it…");
    const actor = `telegram:${cq.from.username ? `@${cq.from.username}` : cq.from.id}`;
    const outcome = await decideFromButton(ctx, cq.data ?? "", actor, { channel: "telegram", chatMatches: matcher });
    if (cq.message) {
      if (outcome.ok) {
        await tg("editMessageReplyMarkup", token, { chat_id: cq.message.chat.id, message_id: cq.message.message_id, reply_markup: { inline_keyboard: [] } }).catch(() => undefined);
      }
      await tg("sendMessage", token, { chat_id: cq.message.chat.id, text: outcome.text, reply_to_message_id: cq.message.message_id }).catch(() => undefined);
    }
    statuses.telegram.lastEventAt = new Date().toISOString();
  }

  /**
   * Bot commands from the owner's phone. Same trust rules as buttons: only the configured chat,
   * and only listed approvers when an approver list is set.
   *   /status  /pending  /lockdown [reason]  /approvalonly [reason]  /resume  /help
   */
  async function handleTelegramMessage(token: string, s: GatewaySettings["notifications"]["telegram"], m: TgMessage): Promise<void> {
    const text = (m.text ?? "").trim();
    if (!text.startsWith("/")) return;
    const reply = (t: string): Promise<unknown> =>
      tg("sendMessage", token, { chat_id: m.chat.id, text: t, reply_to_message_id: m.message_id, disable_web_page_preview: true }).catch(() => undefined);
    const matcher = telegramChatMatcher(m.chat);
    // A client workspace's own chat controls that workspace; the global chat controls the default
    // workspace and the global switch.
    const scoped = ctx.workspaces.list().find((w) => !w.isDefault && w.telegramChatId !== null && matcher(w.telegramChatId));
    if (!scoped && !matcher(s.chatId)) {
      console.error(`[agent-gateway] Ignored a Telegram command from an unexpected chat (${m.chat.id}).`);
      return;
    }
    const approvers = approverList(s.approverIds);
    if (approvers.length > 0 && (!m.from || !approvers.includes(String(m.from.id)))) {
      await reply("You are not on the approver list for this gateway.");
      return;
    }
    const [rawCommand, ...rest] = text.split(/\s+/);
    const command = rawCommand.toLowerCase().replace(/@.*$/, "");
    const reason = rest.join(" ").trim() || null;
    const actor = `telegram:${m.from?.username ? `@${m.from.username}` : (m.from?.id ?? "unknown")}`;
    statuses.telegram.lastEventAt = new Date().toISOString();

    const title = scoped ? `Mont gateway status · ${scoped.name}` : "Mont gateway status";
    switch (command) {
      case "/status": {
        const summary = await buildSummary(ctx, 24, scoped?.id ?? null);
        await reply([title, ...summaryLines(summary)].join("\n"));
        return;
      }
      case "/pending": {
        // Workspace chats see only their own client's queue; the global chat sees the default workspace's.
        const wsId = scoped?.id ?? DEFAULT_WORKSPACE_ID;
        const rows = await ctx.db.all<PendingRow>(
          "SELECT * FROM pending_actions WHERE status = 'PENDING' AND COALESCE(workspace_id, 1) = ? ORDER BY id ASC LIMIT 5",
          [wsId]
        );
        if (rows.length === 0) {
          await reply("Nothing is waiting for approval.");
          return;
        }
        const secret = ctx.settings.approvalSigningSecret();
        for (const row of rows) {
          await sendTelegram(endpoints.telegramApiBase, { ...s, mode: "polling" }, secret, noticeFromRow(row, ctx.workspaces.get(wsId)), null).catch(() => undefined);
        }
        return;
      }
      case "/lockdown":
      case "/approvalonly":
      case "/resume": {
        const mode = command === "/lockdown" ? "lockdown" : command === "/approvalonly" ? "approval_only" : "normal";
        if (scoped) {
          const ws = await ctx.workspaces.setMode(scoped.id, mode, reason, actor);
          await reply(`Done. ${ws.name}: ${modeLabel(ws.mode)}${ws.modeReason ? ` · ${ws.modeReason}` : ""}`);
          return;
        }
        const state = await ctx.emergency.set(mode, reason, actor);
        await reply(`Done. ${modeLabel(state.mode)}${state.reason ? ` · ${state.reason}` : ""}`);
        return;
      }
      case "/start":
      case "/help":
        await reply(
          [
            "Mont gateway commands:",
            "/status: mode, last 24h, money protected, budgets",
            "/pending: requests waiting for you, with Approve / Reject buttons",
            "/lockdown [reason]: refuse every agent request now",
            "/approvalonly [reason]: every write needs your approval",
            "/resume: back to normal",
          ].join("\n")
        );
        return;
      default:
        await reply("Unknown command. Send /help for the list.");
    }
  }

  async function telegramLoop(): Promise<void> {
    let offset = 0;
    let lastToken = "";
    while (!stopped) {
      const s = ctx.settings.get().notifications.telegram;
      if (!s.enabled || s.mode !== "polling" || !s.botToken || !s.chatId) {
        set("telegram", "disabled");
        await releaseLease(ctx, "telegram");
        await nap(5_000);
        continue;
      }
      if (!ctx.license.current().features.interactiveApprovals) {
        set("telegram", "disabled", "Telegram polling (buttons and bot commands) needs a Mont Pro or Agency license.");
        await releaseLease(ctx, "telegram");
        await nap(5_000);
        continue;
      }
      if (s.botToken !== lastToken) {
        offset = 0;
        lastToken = s.botToken;
      }
      const wokenBy = wake.signal;
      try {
        if (!(await holdLease(ctx, "telegram"))) {
          set("telegram", "standby", "Another gateway process sharing this database is polling Telegram.");
          await nap(10_000);
          continue;
        }
        if (statuses.telegram.state !== "connected") set("telegram", "connecting");
        const params = new URLSearchParams({
          timeout: String(endpoints.telegramPollTimeoutSec),
          offset: String(offset),
          allowed_updates: JSON.stringify(["callback_query", "message"]),
        });
        const res = await fetch(`${endpoints.telegramApiBase}/bot${encodeURIComponent(s.botToken)}/getUpdates?${params.toString()}`, {
          signal: AbortSignal.any([wokenBy, AbortSignal.timeout((endpoints.telegramPollTimeoutSec + 15) * 1000)]),
        });
        if (res.status === 409) {
          set("telegram", "error", "Telegram says another program is reading this bot's updates, or a webhook is set on it. Stop the other poller or call deleteWebhook.");
          await res.body?.cancel().catch(() => undefined);
          await nap(15_000);
          continue;
        }
        if (res.status === 401 || res.status === 404) {
          set("telegram", "error", "Telegram rejected the bot token.");
          await res.body?.cancel().catch(() => undefined);
          await nap(30_000);
          continue;
        }
        const data = (await res.json()) as {
          ok?: boolean;
          result?: Array<{ update_id: number; callback_query?: TgCallbackQuery; message?: TgMessage }>;
          description?: string;
        };
        if (!data.ok || !Array.isArray(data.result)) {
          set("telegram", "error", data.description ?? `getUpdates failed (HTTP ${res.status}).`);
          await nap(5_000);
          continue;
        }
        set("telegram", "connected");
        for (const u of data.result) {
          offset = Math.max(offset, u.update_id + 1);
          if (u.callback_query) {
            await handleTelegramCallback(s.botToken, s, u.callback_query).catch((err: unknown) => console.error("Telegram button handling failed:", err));
          }
          if (u.message) {
            await handleTelegramMessage(s.botToken, s, u.message).catch((err: unknown) => console.error("Telegram command handling failed:", err));
          }
        }
        if (endpoints.telegramPollTimeoutSec === 0) await nap(1_000); // short-polling: do not spin
      } catch (err) {
        if (stopped) break;
        if (wokenBy.aborted) continue; // kick(): settings changed, loop around immediately
        set("telegram", "error", err instanceof Error ? err.message : String(err));
        await nap(5_000);
      }
    }
    await releaseLease(ctx, "telegram");
  }

  // ---------------- Slack Socket Mode ----------------
  async function slackApi(method: string, token: string, body: unknown): Promise<{ ok?: boolean; error?: string; url?: string }> {
    const r = await postJson(`${endpoints.slackApiBase}/${method}`, body, { authorization: `Bearer ${token}` });
    return (r.json ?? {}) as { ok?: boolean; error?: string; url?: string };
  }

  async function handleSlackAction(s: GatewaySettings["notifications"]["slack"], p: SlackBlockActions): Promise<void> {
    const action = p.actions?.[0];
    if (!action || (action.action_id !== "mont_approve" && action.action_id !== "mont_reject")) return;
    const channelId = p.channel?.id ?? "";
    // The global channel, or a client workspace's own channel.
    if (!channelId || (channelId !== s.channelId && !ctx.workspaces.list().some((w) => w.slackChannel === channelId))) {
      console.error(`[agent-gateway] Ignored a Slack button from an unexpected channel (${p.channel?.id ?? "none"}).`);
      return;
    }
    const userId = p.user?.id ?? "";
    const approvers = approverList(s.approverIds);
    const reply = (text: string): Promise<unknown> =>
      p.message ? slackApi("chat.postMessage", s.botToken, { channel: channelId, thread_ts: p.message.ts, text }).catch(() => undefined) : Promise.resolve();
    if (approvers.length > 0 && !approvers.includes(userId)) {
      await reply(`<@${userId}> is not on the approver list for this gateway; nothing was changed.`);
      return;
    }
    if (action.value === TEST_BUTTON_TOKEN) {
      await reply("Test button works. Real buttons approve or reject the request.");
      return;
    }
    const actor = `slack:${p.user?.username ?? p.user?.name ?? userId}`;
    const outcome = await decideFromButton(ctx, action.value ?? "", actor, { channel: "slack", channelId });
    if (outcome.ok && p.message) {
      await slackApi("chat.update", s.botToken, {
        channel: channelId,
        ts: p.message.ts,
        text: outcome.text,
        blocks: [{ type: "section", text: { type: "mrkdwn", text: escSlack(outcome.text) } }],
      }).catch(() => undefined);
    } else {
      await reply(outcome.text);
    }
    statuses.slack.lastEventAt = new Date().toISOString();
  }

  async function slackLoop(): Promise<void> {
    while (!stopped) {
      const s = ctx.settings.get().notifications.slack;
      if (!s.enabled || s.mode !== "socket" || !s.appToken || !s.botToken || !s.channelId) {
        set("slack", "disabled");
        await releaseLease(ctx, "slack");
        await nap(5_000);
        continue;
      }
      if (!ctx.license.current().features.interactiveApprovals) {
        set("slack", "disabled", "Slack Socket Mode buttons need a Mont Pro or Agency license.");
        await releaseLease(ctx, "slack");
        await nap(5_000);
        continue;
      }
      try {
        if (!(await holdLease(ctx, "slack"))) {
          set("slack", "standby", "Another gateway process sharing this database holds the Slack connection.");
          await nap(10_000);
          continue;
        }
        set("slack", "connecting");
        const open = await slackApi("apps.connections.open", s.appToken, {});
        if (!open.ok || !open.url) {
          set("slack", "error", `apps.connections.open failed: ${open.error ?? "no url"} (check the xapp- token has connections:write).`);
          await nap(15_000);
          continue;
        }
        await new Promise<void>((resolve) => {
          const ws = new WebSocket(open.url as string);
          currentSocket = ws;
          const renew = setInterval(() => {
            holdLease(ctx, "slack")
              .then((held) => {
                if (!held) ws.close();
              })
              .catch(() => ws.close());
          }, 20_000);
          renew.unref();
          const done = (): void => {
            clearInterval(renew);
            if (currentSocket === ws) currentSocket = null;
            resolve();
          };
          ws.addEventListener("open", () => set("slack", "connected"));
          ws.addEventListener("close", done);
          ws.addEventListener("error", () => {
            set("slack", "error", "Socket Mode connection error.");
            try {
              ws.close();
            } catch {
              done();
            }
          });
          ws.addEventListener("message", (ev: MessageEvent) => {
            let msg: { type?: string; envelope_id?: string; payload?: unknown };
            try {
              msg = JSON.parse(typeof ev.data === "string" ? ev.data : Buffer.from(ev.data as ArrayBuffer).toString("utf8")) as typeof msg;
            } catch {
              return;
            }
            // Acknowledge first: Slack retries anything not acked within 3 seconds.
            if (msg.envelope_id) ws.send(JSON.stringify({ envelope_id: msg.envelope_id }));
            if (msg.type === "disconnect") {
              ws.close();
              return;
            }
            const payload = msg.payload as SlackBlockActions | undefined;
            if (msg.type === "interactive" && payload?.type === "block_actions") {
              void handleSlackAction(ctx.settings.get().notifications.slack, payload).catch((err: unknown) => console.error("Slack button handling failed:", err));
            }
          });
        });
        if (!stopped) await nap(1_000); // reconnect after a short pause
      } catch (err) {
        if (stopped) break;
        set("slack", "error", err instanceof Error ? err.message : String(err));
        await nap(5_000);
      }
    }
    await releaseLease(ctx, "slack");
  }

  return {
    start() {
      if (!stopped) return;
      stopped = false;
      wake = new AbortController();
      loops.push(telegramLoop(), slackLoop());
    },
    async stop() {
      stopped = true;
      wake.abort();
      currentSocket?.close();
      await Promise.allSettled(loops.splice(0));
    },
    kick() {
      const old = wake;
      wake = new AbortController();
      old.abort();
      currentSocket?.close();
    },
    status: () => structuredClone(statuses),
  };
}
