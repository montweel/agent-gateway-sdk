"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TEST_BUTTON_TOKEN = void 0;
exports.workspaceNotice = workspaceNotice;
exports.signWebhookBody = signWebhookBody;
exports.createNotifier = createNotifier;
exports.noticeFromRow = noticeFromRow;
exports.createApprovalBridges = createApprovalBridges;
const crypto_1 = __importDefault(require("crypto"));
const constants_1 = require("./constants");
const approvalSigning_1 = require("./approvalSigning");
const utils_1 = require("./utils");
const protection_1 = require("./protection");
function workspaceNotice(ws) {
    if (!ws)
        return null;
    return { id: ws.id, name: ws.name, slug: ws.slug, isDefault: ws.isDefault, telegramChatId: ws.telegramChatId, slackChannel: ws.slackChannel };
}
/** "[Acme Outfitters] " for client workspaces, "" for the default one. */
function wsLabel(n) {
    return n.workspace && !n.workspace.isDefault ? `[${n.workspace.name}] ` : "";
}
exports.TEST_BUTTON_TOKEN = "mont:test";
// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
function prettyBody(body) {
    if (!body)
        return "(no body)";
    let text;
    try {
        text = JSON.stringify(JSON.parse(body), null, 2);
    }
    catch {
        text = body;
    }
    return text.length > constants_1.MAX_NOTIFY_PAYLOAD_CHARS ? `${text.slice(0, constants_1.MAX_NOTIFY_PAYLOAD_CHARS)}\n… [truncated]` : text;
}
function riskLines(body) {
    if (!body)
        return [];
    try {
        return (0, utils_1.findHighRiskFields)(JSON.parse(body)).map((f) => `${f.path} = ${JSON.stringify(f.value)}`);
    }
    catch {
        return [];
    }
}
function callerLine(n) {
    const parts = [];
    if (n.agentKey)
        parts.push(`key "${n.agentKey}"${n.agentKeyPrefix ? ` (${n.agentKeyPrefix}…)` : ""}`);
    if (n.callerIp)
        parts.push(`IP ${n.callerIp}`);
    if (n.callerUa)
        parts.push(`UA ${n.callerUa.slice(0, 80)}`);
    return parts.join(" · ") || "unknown caller";
}
function links(settings, secret, n) {
    if (!settings.publicBaseUrl)
        return null;
    const exp = Math.min(n.expiresAt, Date.now() + constants_1.PENDING_TTL_MS);
    return {
        approve: (0, approvalSigning_1.buildApprovalLink)(settings.publicBaseUrl, secret, { id: n.id, decision: "APPROVE", exp, queuedAt: n.queuedAt }),
        reject: (0, approvalSigning_1.buildApprovalLink)(settings.publicBaseUrl, secret, { id: n.id, decision: "REJECT", exp, queuedAt: n.queuedAt }),
    };
}
function buttonTokens(secret, n) {
    if (n.id === 0)
        return { approve: exports.TEST_BUTTON_TOKEN, reject: exports.TEST_BUTTON_TOKEN };
    return { approve: (0, approvalSigning_1.signButtonToken)(secret, n.id, "APPROVE", n.queuedAt), reject: (0, approvalSigning_1.signButtonToken)(secret, n.id, "REJECT", n.queuedAt) };
}
const escSlack = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const escHtml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/** Body signature for receivers: hex HMAC-SHA256 over "<timestamp>.<raw body>". */
function signWebhookBody(secret, timestamp, body) {
    return crypto_1.default.createHmac("sha256", secret).update(`${timestamp}.${body}`, "utf8").digest("hex");
}
async function postJson(url, body, headers = {}) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json; charset=utf-8", ...headers },
        body: typeof body === "string" ? body : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(constants_1.NOTIFY_TIMEOUT_MS),
    });
    const text = (await res.text().catch(() => "")).slice(0, 2000);
    let json = null;
    try {
        json = JSON.parse(text);
    }
    catch {
        json = null;
    }
    return { status: res.status, json, text };
}
function slackOk(r) {
    const ok = r.status >= 200 && r.status < 300 && (r.json === null || r.json.ok !== false);
    const err = r.json?.error;
    return { channel: "slack", ok, status: r.status, ...(ok ? {} : { error: typeof err === "string" ? err : r.text.slice(0, 300) }) };
}
function slackText(n) {
    const risks = riskLines(n.body);
    return (`*${escSlack(n.method)}* \`${escSlack(n.path)}\`\n` +
        `*Caller:* ${escSlack(callerLine(n))}\n` +
        (n.agentReason ? `*Agent's reason:* ${escSlack(n.agentReason.slice(0, 300))}\n` : "") +
        (n.matchedPolicy ? `*Matched:* ${escSlack(n.matchedPolicy)}\n` : "") +
        (risks.length ? `:warning: *High-risk fields:* ${escSlack(risks.join(", "))}` : ""));
}
function slackBlocks(n, actions, footer) {
    const blocks = [
        { type: "header", text: { type: "plain_text", text: n.id === 0 ? "Test notification" : `${wsLabel(n)}Approval needed: #${n.id}`.slice(0, 150), emoji: false } },
        { type: "section", text: { type: "mrkdwn", text: slackText(n) } },
        { type: "section", text: { type: "mrkdwn", text: "```" + escSlack(prettyBody(n.body)).replace(/```/g, "'''") + "```" } },
    ];
    if (actions)
        blocks.push(actions);
    if (footer)
        blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: footer }] });
    return blocks;
}
function telegramText(n, footer) {
    const risks = riskLines(n.body);
    return (`<b>${n.id === 0 ? "Test notification" : `${escHtml(wsLabel(n))}Approval needed: #${n.id}`}</b>\n` +
        `<b>${escHtml(n.method)}</b> <code>${escHtml(n.path)}</code>\n` +
        `<b>Caller:</b> ${escHtml(callerLine(n))}\n` +
        (n.agentReason ? `<b>Agent's reason:</b> ${escHtml(n.agentReason.slice(0, 300))}\n` : "") +
        (n.matchedPolicy ? `<b>Matched:</b> ${escHtml(n.matchedPolicy)}\n` : "") +
        (risks.length ? `⚠️ <b>High-risk fields:</b> ${escHtml(risks.join(", "))}\n` : "") +
        `<pre>${escHtml(prettyBody(n.body))}</pre>` +
        (footer ? `\n${escHtml(footer)}` : ""));
}
// ---------------------------------------------------------------------------
// Senders
// ---------------------------------------------------------------------------
async function sendSlackWebhook(webhookUrl, n, l) {
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
async function sendSlackBot(base, s, secret, n, interactive) {
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
    const r = await postJson(`${base}/chat.postMessage`, {
        channel: n.workspace?.slackChannel || s.channelId,
        text: `${wsLabel(n)}Approval needed: ${n.method} ${n.path} (#${n.id})`,
        blocks: slackBlocks(n, actions, interactive ? null : PRO_BUTTONS_FOOTER),
        unfurl_links: false,
    }, { authorization: `Bearer ${s.botToken}` });
    return slackOk(r);
}
async function sendTelegram(base, s, secret, n, l, interactive = true) {
    const payload = { chat_id: n.workspace?.telegramChatId || s.chatId, parse_mode: "HTML", disable_web_page_preview: true };
    if (s.mode === "polling" && !interactive) {
        // Community: the message still arrives; buttons fall back to signed links when a Public URL exists.
        payload.text = telegramText(n, l ? null : PRO_BUTTONS_FOOTER);
        if (l)
            payload.reply_markup = { inline_keyboard: [[{ text: "✅ Approve", url: l.approve }, { text: "⛔ Reject", url: l.reject }]] };
    }
    else if (s.mode === "polling") {
        const t = buttonTokens(secret, n);
        payload.text = telegramText(n, null);
        payload.reply_markup = { inline_keyboard: [[{ text: "✅ Approve", callback_data: t.approve }, { text: "⛔ Reject", callback_data: t.reject }]] };
    }
    else if (l) {
        payload.text = telegramText(n, null);
        payload.reply_markup = { inline_keyboard: [[{ text: "✅ Approve", url: l.approve }, { text: "⛔ Reject", url: l.reject }]] };
    }
    else {
        payload.text = telegramText(n, "Set a Public URL in Gateway Setup, or switch Telegram to polling mode, to get one-tap buttons.");
    }
    const r = await postJson(`${base}/bot${encodeURIComponent(s.botToken)}/sendMessage`, payload);
    const ok = r.status >= 200 && r.status < 300;
    // Never echo the bot token in an error.
    return { channel: "telegram", ok, status: r.status, ...(ok ? {} : { error: r.text.split(s.botToken).join("[token]").slice(0, 300) }) };
}
async function sendWebhook(url, secret, n, l) {
    let parsedBody = null;
    try {
        parsedBody = n.body ? JSON.parse(n.body) : null;
    }
    catch {
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
    const headers = { "x-mont-event": "approval.pending", "x-mont-timestamp": ts };
    if (secret)
        headers["x-mont-signature"] = `sha256=${signWebhookBody(secret, ts, body)}`;
    const r = await postJson(url, body, headers);
    const ok = r.status >= 200 && r.status < 300;
    return { channel: "webhook", ok, status: r.status, ...(ok ? {} : { error: r.text.slice(0, 300) }) };
}
// ---------------------------------------------------------------------------
// Notifier
// ---------------------------------------------------------------------------
function createNotifier(settingsStore, redactor, endpoints, 
/** Current license features (zero-tunnel buttons are Pro / Agency). */
features) {
    async function dispatch(raw) {
        let settings;
        let secret;
        try {
            settings = settingsStore.get();
            secret = settingsStore.approvalSigningSecret();
        }
        catch (err) {
            console.error("Notifications skipped:", err);
            return [];
        }
        // Defence in depth: callers pass already-redacted data, but nothing leaves unscrubbed.
        const n = {
            ...raw,
            path: redactor.text(raw.path),
            body: redactor.jsonText(raw.body),
            query: redactor.json(raw.query),
            callerUa: raw.callerUa ? redactor.text(raw.callerUa) : null,
            agentReason: raw.agentReason ? redactor.text(raw.agentReason) : null,
        };
        const l = links(settings, secret, n);
        const { slack, telegram, webhook } = settings.notifications;
        const interactive = features().interactiveApprovals;
        const jobs = [];
        const guard = (channel, p) => p.catch((err) => ({ channel, ok: false, error: err instanceof Error ? err.message : String(err) }));
        if (slack.enabled) {
            const channel = n.workspace?.slackChannel || slack.channelId;
            if (slack.mode === "socket" && slack.botToken && channel)
                jobs.push(guard("slack", sendSlackBot(endpoints.slackApiBase, slack, secret, n, interactive)));
            else if (slack.mode === "webhook" && slack.webhookUrl)
                jobs.push(guard("slack", sendSlackWebhook(slack.webhookUrl, n, l)));
        }
        if (telegram.enabled && telegram.botToken && (n.workspace?.telegramChatId || telegram.chatId)) {
            jobs.push(guard("telegram", sendTelegram(endpoints.telegramApiBase, telegram, secret, n, l, interactive)));
        }
        if (webhook.enabled && webhook.url)
            jobs.push(guard("webhook", sendWebhook(webhook.url, webhook.secret, n, l)));
        const results = await Promise.all(jobs);
        for (const r of results) {
            if (!r.ok)
                console.error(`[agent-gateway] ${r.channel} notification failed:`, r.status ?? "", r.error ?? "");
        }
        return results;
    }
    async function alert(rawTitle, rawLines) {
        let settings;
        try {
            settings = settingsStore.get();
        }
        catch {
            return [];
        }
        const title = redactor.text(rawTitle);
        const lines = rawLines.map((l) => redactor.text(l));
        const { slack, telegram, webhook } = settings.notifications;
        const jobs = [];
        const guard = (channel, p) => p.catch((err) => ({ channel, ok: false, error: err instanceof Error ? err.message : String(err) }));
        if (slack.enabled) {
            const text = `*${escSlack(title)}*\n${lines.map((l) => `• ${escSlack(l)}`).join("\n")}`;
            if (slack.mode === "socket" && slack.botToken && slack.channelId) {
                jobs.push(guard("slack", postJson(`${endpoints.slackApiBase}/chat.postMessage`, { channel: slack.channelId, text }, { authorization: `Bearer ${slack.botToken}` }).then(slackOk)));
            }
            else if (slack.mode === "webhook" && slack.webhookUrl) {
                jobs.push(guard("slack", postJson(slack.webhookUrl, { text }).then(slackOk)));
            }
        }
        if (telegram.enabled && telegram.botToken && telegram.chatId) {
            const text = `<b>${escHtml(title)}</b>\n${lines.map((l) => `• ${escHtml(l)}`).join("\n")}`;
            jobs.push(guard("telegram", postJson(`${endpoints.telegramApiBase}/bot${encodeURIComponent(telegram.botToken)}/sendMessage`, { chat_id: telegram.chatId, text, parse_mode: "HTML" }).then((r) => ({
                channel: "telegram",
                ok: r.status >= 200 && r.status < 300,
                status: r.status,
            }))));
        }
        if (webhook.enabled && webhook.url) {
            const body = JSON.stringify({ event: "alert", title, lines, at: new Date().toISOString() });
            const ts = String(Math.floor(Date.now() / 1000));
            const headers = { "x-mont-event": "alert", "x-mont-timestamp": ts };
            if (webhook.secret)
                headers["x-mont-signature"] = `sha256=${signWebhookBody(webhook.secret, ts, body)}`;
            jobs.push(guard("webhook", postJson(webhook.url, body, headers).then((r) => ({ channel: "webhook", ok: r.status >= 200 && r.status < 300, status: r.status }))));
        }
        return Promise.all(jobs);
    }
    return {
        sendAlert: (title, lines) => alert(title, lines).catch(() => []),
        notifyPending: (n) => dispatch(n).catch(() => []),
        sendTest: () => dispatch({
            id: 0,
            queuedAt: new Date().toISOString(),
            expiresAt: Date.now() + 10 * 60000,
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
const LEASE_TTL_MS = 60000;
/** One poller per channel across every gateway process sharing this database. */
async function holdLease(ctx, channel) {
    const key = `bridge_lease:${channel}`;
    const now = Date.now();
    const value = JSON.stringify({ owner: ctx.instanceId, expiresAt: now + LEASE_TTL_MS });
    const r = await ctx.db.run(`INSERT INTO system_settings (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value
     WHERE json_extract(system_settings.value, '$.owner') = ? OR json_extract(system_settings.value, '$.expiresAt') < ?`, [key, value, ctx.instanceId, now]);
    return r.changes > 0;
}
async function releaseLease(ctx, channel) {
    await ctx.db
        .run("DELETE FROM system_settings WHERE key = ? AND json_extract(value, '$.owner') = ?", [`bridge_lease:${channel}`, ctx.instanceId])
        .catch(() => undefined);
}
function approverList(raw) {
    return raw
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
}
/** Rebuilds a notification from a stored (already redacted) approval row. */
function noticeFromRow(row, workspace) {
    let query = {};
    try {
        query = row.query_json ? JSON.parse(row.query_json) : {};
    }
    catch {
        query = {};
    }
    return {
        id: row.id,
        queuedAt: row.timestamp,
        expiresAt: row.expires_at ?? Date.now() + constants_1.PENDING_TTL_MS,
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
function telegramChatMatcher(chat) {
    return (configured) => {
        const c = configured.trim();
        return c !== "" && (String(chat.id) === c || (c.startsWith("@") && chat.username?.toLowerCase() === c.slice(1).toLowerCase()));
    };
}
/** Verifies a button token against its queued row and applies the decision. */
async function decideFromButton(ctx, token, actor, origin) {
    const parsed = (0, approvalSigning_1.parseButtonToken)(token);
    if (!parsed)
        return { ok: false, text: "This button is not valid." };
    const row = await ctx.db.get("SELECT id, timestamp, workspace_id FROM pending_actions WHERE id = ?", [parsed.id]);
    if (!row || !(0, approvalSigning_1.verifyButtonToken)(ctx.settings.approvalSigningSecret(), parsed, row.timestamp)) {
        return { ok: false, text: "This button is not valid for that request." };
    }
    // The request's workspace decides which chat / channel may approve it.
    const ws = ctx.workspaces.get(row.workspace_id ?? constants_1.DEFAULT_WORKSPACE_ID);
    const n = ctx.settings.get().notifications;
    const allowed = origin.channel === "telegram"
        ? origin.chatMatches(ws?.telegramChatId || n.telegram.chatId)
        : origin.channelId === (ws?.slackChannel || n.slack.channelId);
    if (!allowed) {
        console.error(`[agent-gateway] Refused a ${origin.channel} button for action #${parsed.id} from a chat that does not belong to its workspace.`);
        return { ok: false, text: `#${parsed.id} belongs to another client workspace; it can only be decided from that workspace's chat or the dashboard.` };
    }
    const result = await ctx.approvals.decide(parsed.id, parsed.decision, actor);
    const body = result.body;
    if (result.status >= 200 && result.status < 300) {
        const verb = body.status === "REJECTED" ? "⛔ Rejected" : body.status === "EXECUTING" ? "✅ Approved (executing)" : "✅ Approved and executed";
        return { ok: true, text: `${verb} #${parsed.id} by ${actor}${body.replayStatus !== undefined ? ` · target replied HTTP ${body.replayStatus}` : ""}` };
    }
    return { ok: false, text: `#${parsed.id} not changed: ${body.message ?? "it could not be decided."}` };
}
function createApprovalBridges(ctx, endpoints) {
    let stopped = true;
    const statuses = {
        telegram: { state: "disabled", detail: null, lastEventAt: null },
        slack: { state: "disabled", detail: null, lastEventAt: null },
    };
    let wake = new AbortController();
    const loops = [];
    let currentSocket = null;
    const set = (ch, state, detail = null) => {
        statuses[ch].state = state;
        statuses[ch].detail = detail;
    };
    /** Sleeps, but wakes early on kick() / stop(). */
    const nap = (ms) => new Promise((resolve) => {
        const signal = wake.signal;
        // Already woken (stop()/kick() ran while we were busy): an abort listener would never fire.
        if (stopped || signal.aborted) {
            resolve();
            return;
        }
        const t = setTimeout(done, ms);
        t.unref();
        function done() {
            clearTimeout(t);
            signal.removeEventListener("abort", done);
            resolve();
        }
        signal.addEventListener("abort", done, { once: true });
    });
    // ---------------- Telegram ----------------
    async function tg(method, token, body) {
        const r = await postJson(`${endpoints.telegramApiBase}/bot${encodeURIComponent(token)}/${method}`, body);
        return r.json;
    }
    async function handleTelegramCallback(token, s, cq) {
        const answer = (text, alert = false) => tg("answerCallbackQuery", token, { callback_query_id: cq.id, text: text.slice(0, 190), show_alert: alert }).catch(() => undefined);
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
        if (cq.data === exports.TEST_BUTTON_TOKEN) {
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
    async function handleTelegramMessage(token, s, m) {
        const text = (m.text ?? "").trim();
        if (!text.startsWith("/"))
            return;
        const reply = (t) => tg("sendMessage", token, { chat_id: m.chat.id, text: t, reply_to_message_id: m.message_id, disable_web_page_preview: true }).catch(() => undefined);
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
                const summary = await (0, protection_1.buildSummary)(ctx, 24, scoped?.id ?? null);
                await reply([title, ...(0, protection_1.summaryLines)(summary)].join("\n"));
                return;
            }
            case "/pending": {
                // Workspace chats see only their own client's queue; the global chat sees the default workspace's.
                const wsId = scoped?.id ?? constants_1.DEFAULT_WORKSPACE_ID;
                const rows = await ctx.db.all("SELECT * FROM pending_actions WHERE status = 'PENDING' AND COALESCE(workspace_id, 1) = ? ORDER BY id ASC LIMIT 5", [wsId]);
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
                    await reply(`Done. ${ws.name}: ${(0, protection_1.modeLabel)(ws.mode)}${ws.modeReason ? ` · ${ws.modeReason}` : ""}`);
                    return;
                }
                const state = await ctx.emergency.set(mode, reason, actor);
                await reply(`Done. ${(0, protection_1.modeLabel)(state.mode)}${state.reason ? ` · ${state.reason}` : ""}`);
                return;
            }
            case "/start":
            case "/help":
                await reply([
                    "Mont gateway commands:",
                    "/status: mode, last 24h, money protected, budgets",
                    "/pending: requests waiting for you, with Approve / Reject buttons",
                    "/lockdown [reason]: refuse every agent request now",
                    "/approvalonly [reason]: every write needs your approval",
                    "/resume: back to normal",
                ].join("\n"));
                return;
            default:
                await reply("Unknown command. Send /help for the list.");
        }
    }
    async function telegramLoop() {
        let offset = 0;
        let lastToken = "";
        while (!stopped) {
            const s = ctx.settings.get().notifications.telegram;
            if (!s.enabled || s.mode !== "polling" || !s.botToken || !s.chatId) {
                set("telegram", "disabled");
                await releaseLease(ctx, "telegram");
                await nap(5000);
                continue;
            }
            if (!ctx.license.current().features.interactiveApprovals) {
                set("telegram", "disabled", "Telegram polling (buttons and bot commands) needs a Mont Pro or Agency license.");
                await releaseLease(ctx, "telegram");
                await nap(5000);
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
                    await nap(10000);
                    continue;
                }
                if (statuses.telegram.state !== "connected")
                    set("telegram", "connecting");
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
                    await nap(15000);
                    continue;
                }
                if (res.status === 401 || res.status === 404) {
                    set("telegram", "error", "Telegram rejected the bot token.");
                    await res.body?.cancel().catch(() => undefined);
                    await nap(30000);
                    continue;
                }
                const data = (await res.json());
                if (!data.ok || !Array.isArray(data.result)) {
                    set("telegram", "error", data.description ?? `getUpdates failed (HTTP ${res.status}).`);
                    await nap(5000);
                    continue;
                }
                set("telegram", "connected");
                for (const u of data.result) {
                    offset = Math.max(offset, u.update_id + 1);
                    if (u.callback_query) {
                        await handleTelegramCallback(s.botToken, s, u.callback_query).catch((err) => console.error("Telegram button handling failed:", err));
                    }
                    if (u.message) {
                        await handleTelegramMessage(s.botToken, s, u.message).catch((err) => console.error("Telegram command handling failed:", err));
                    }
                }
                if (endpoints.telegramPollTimeoutSec === 0)
                    await nap(1000); // short-polling: do not spin
            }
            catch (err) {
                if (stopped)
                    break;
                if (wokenBy.aborted)
                    continue; // kick(): settings changed, loop around immediately
                set("telegram", "error", err instanceof Error ? err.message : String(err));
                await nap(5000);
            }
        }
        await releaseLease(ctx, "telegram");
    }
    // ---------------- Slack Socket Mode ----------------
    async function slackApi(method, token, body) {
        const r = await postJson(`${endpoints.slackApiBase}/${method}`, body, { authorization: `Bearer ${token}` });
        return (r.json ?? {});
    }
    async function handleSlackAction(s, p) {
        const action = p.actions?.[0];
        if (!action || (action.action_id !== "mont_approve" && action.action_id !== "mont_reject"))
            return;
        const channelId = p.channel?.id ?? "";
        // The global channel, or a client workspace's own channel.
        if (!channelId || (channelId !== s.channelId && !ctx.workspaces.list().some((w) => w.slackChannel === channelId))) {
            console.error(`[agent-gateway] Ignored a Slack button from an unexpected channel (${p.channel?.id ?? "none"}).`);
            return;
        }
        const userId = p.user?.id ?? "";
        const approvers = approverList(s.approverIds);
        const reply = (text) => p.message ? slackApi("chat.postMessage", s.botToken, { channel: channelId, thread_ts: p.message.ts, text }).catch(() => undefined) : Promise.resolve();
        if (approvers.length > 0 && !approvers.includes(userId)) {
            await reply(`<@${userId}> is not on the approver list for this gateway; nothing was changed.`);
            return;
        }
        if (action.value === exports.TEST_BUTTON_TOKEN) {
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
        }
        else {
            await reply(outcome.text);
        }
        statuses.slack.lastEventAt = new Date().toISOString();
    }
    async function slackLoop() {
        while (!stopped) {
            const s = ctx.settings.get().notifications.slack;
            if (!s.enabled || s.mode !== "socket" || !s.appToken || !s.botToken || !s.channelId) {
                set("slack", "disabled");
                await releaseLease(ctx, "slack");
                await nap(5000);
                continue;
            }
            if (!ctx.license.current().features.interactiveApprovals) {
                set("slack", "disabled", "Slack Socket Mode buttons need a Mont Pro or Agency license.");
                await releaseLease(ctx, "slack");
                await nap(5000);
                continue;
            }
            try {
                if (!(await holdLease(ctx, "slack"))) {
                    set("slack", "standby", "Another gateway process sharing this database holds the Slack connection.");
                    await nap(10000);
                    continue;
                }
                set("slack", "connecting");
                const open = await slackApi("apps.connections.open", s.appToken, {});
                if (!open.ok || !open.url) {
                    set("slack", "error", `apps.connections.open failed: ${open.error ?? "no url"} (check the xapp- token has connections:write).`);
                    await nap(15000);
                    continue;
                }
                await new Promise((resolve) => {
                    const ws = new WebSocket(open.url);
                    currentSocket = ws;
                    const renew = setInterval(() => {
                        holdLease(ctx, "slack")
                            .then((held) => {
                            if (!held)
                                ws.close();
                        })
                            .catch(() => ws.close());
                    }, 20000);
                    renew.unref();
                    const done = () => {
                        clearInterval(renew);
                        if (currentSocket === ws)
                            currentSocket = null;
                        resolve();
                    };
                    ws.addEventListener("open", () => set("slack", "connected"));
                    ws.addEventListener("close", done);
                    ws.addEventListener("error", () => {
                        set("slack", "error", "Socket Mode connection error.");
                        try {
                            ws.close();
                        }
                        catch {
                            done();
                        }
                    });
                    ws.addEventListener("message", (ev) => {
                        let msg;
                        try {
                            msg = JSON.parse(typeof ev.data === "string" ? ev.data : Buffer.from(ev.data).toString("utf8"));
                        }
                        catch {
                            return;
                        }
                        // Acknowledge first: Slack retries anything not acked within 3 seconds.
                        if (msg.envelope_id)
                            ws.send(JSON.stringify({ envelope_id: msg.envelope_id }));
                        if (msg.type === "disconnect") {
                            ws.close();
                            return;
                        }
                        const payload = msg.payload;
                        if (msg.type === "interactive" && payload?.type === "block_actions") {
                            void handleSlackAction(ctx.settings.get().notifications.slack, payload).catch((err) => console.error("Slack button handling failed:", err));
                        }
                    });
                });
                if (!stopped)
                    await nap(1000); // reconnect after a short pause
            }
            catch (err) {
                if (stopped)
                    break;
                set("slack", "error", err instanceof Error ? err.message : String(err));
                await nap(5000);
            }
        }
        await releaseLease(ctx, "slack");
    }
    return {
        start() {
            if (!stopped)
                return;
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
