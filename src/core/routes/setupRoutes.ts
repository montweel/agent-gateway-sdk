import type { Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest, GatewaySettings } from "../types";
import { randomHex } from "../crypto";
import { parseTargetUrl, sendError, sendInternalError } from "../utils";
import { POLICY_PRESETS, applyPreset, findPreset } from "../presets";
import { HHMM, isValidTimeZone } from "../settingsStore";
import { isWithinBusinessHours } from "../operatingMode";
import { validateResponseGuard } from "../responseGuard";
import { requireWorkspace } from "./scope";

/**
 * No-Code Setup wizard API.
 *
 *   GET  /setup                    everything the wizard shows
 *   POST /setup                    partial update (only the fields sent are changed)
 *   POST /setup/test-notification  sends a sample notice to every enabled channel
 *
 * Storage: listen port, public URL, notification channels and the rollback webhook live in
 * SQLite (system_settings). Upstream URL and global rate limit stay in config.json, which is
 * the single source of truth the interceptor already reads on every request; the wizard
 * writes them through the same validated config store as the Settings tab.
 */

const SLACK_PREFIX = "https://hooks.slack.com/";
const TELEGRAM_TOKEN = /^\d{5,15}:[A-Za-z0-9_-]{30,64}$/;
const TELEGRAM_CHAT = /^(?:-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/;
const MASK = "••••••••";

function mask(value: string): string {
  if (!value) return "";
  return value.length <= 8 ? MASK : `${MASK}${value.slice(-4)}`;
}

function viewForRole(s: GatewaySettings, isAdmin: boolean): GatewaySettings {
  if (isAdmin) return s;
  return {
    ...s,
    notifications: {
      slack: {
        ...s.notifications.slack,
        webhookUrl: mask(s.notifications.slack.webhookUrl),
        botToken: mask(s.notifications.slack.botToken),
        appToken: mask(s.notifications.slack.appToken),
      },
      telegram: { ...s.notifications.telegram, botToken: mask(s.notifications.telegram.botToken) },
      webhook: { ...s.notifications.webhook, secret: mask(s.notifications.webhook.secret) },
    },
    rollback: { ...s.rollback, secret: mask(s.rollback.secret) },
  };
}

type Check<T> = { ok: true; value: T } | { ok: false; message: string };

function checkPublicBaseUrl(v: unknown): Check<string> {
  if (typeof v !== "string") return { ok: false, message: "publicBaseUrl must be a string." };
  const trimmed = v.trim().replace(/\/+$/, "");
  if (trimmed === "") return { ok: true, value: "" };
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return { ok: false, message: "publicBaseUrl must be a full URL like https://gateway.example.com" };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, message: "publicBaseUrl must start with https:// (or http:// for local testing)." };
  if (u.username || u.password) return { ok: false, message: "publicBaseUrl must not contain credentials." };
  if (u.search || u.hash) return { ok: false, message: "publicBaseUrl must not contain a query string or fragment." };
  return { ok: true, value: trimmed };
}

const SLACK_BOT_TOKEN = /^xoxb-[A-Za-z0-9-]{10,200}$/;
const SLACK_APP_TOKEN = /^xapp-[A-Za-z0-9-]{10,200}$/;
const SLACK_CHANNEL = /^[CGD][A-Z0-9]{6,20}$/;
const SLACK_USER = /^[UW][A-Z0-9]{6,20}$/;

function checkApprovers(v: unknown, idPattern: RegExp, message: string): Check<string> {
  if (typeof v !== "string" || v.length > 2000) return { ok: false, message };
  const ids = v.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  if (!ids.every((id) => idPattern.test(id))) return { ok: false, message };
  return { ok: true, value: ids.join(", ") };
}

function checkSecret(v: unknown, field: string): Check<string> {
  if (typeof v !== "string" || v.length > 256) return { ok: false, message: `${field} must be a string of at most 256 characters.` };
  return { ok: true, value: v.trim() };
}

export function registerSetupRoutes(router: Router, ctx: GatewayContext): void {
  const { config: configStore, settings, notifier, port } = ctx;

  function snapshot(isAdmin: boolean) {
    const cfg = configStore.load();
    return {
      gateway: { targetUrl: cfg.targetUrl, rateLimitPerMinute: cfg.rateLimitPerMinute, gatewayPort: port },
      settings: viewForRole(settings.get(), isAdmin),
      callbackPathPrefix: "/_mont/approvals",
      bridges: ctx.bridges.status(),
      emergency: ctx.emergency.current(),
      withinBusinessHours: isWithinBusinessHours(settings.peek().schedule, settings.peek().timezone),
    };
  }

  // ---- Starter policy packs ----
  router.get("/setup/presets", (_req: AuthenticatedRequest, res: Response) => {
    res.json(POLICY_PRESETS.map((p) => ({ id: p.id, name: p.name, summary: p.summary, highlights: p.highlights, rules: p.rules })));
  });

  /** Body: { mode: "merge" | "replace" }. merge keeps your other rules; pack rules win on the same key. */
  router.post("/setup/presets/:id/apply", async (req: AuthenticatedRequest, res: Response) => {
    if (req.user?.role !== "admin") {
      sendError(res, 403, "Forbidden", "Only administrators can install policy packs.");
      return;
    }
    const preset = findPreset(String(req.params.id));
    if (!preset) {
      sendError(res, 404, "Not Found", `No policy pack "${String(req.params.id)}". Use one of: ${POLICY_PRESETS.map((p) => p.id).join(", ")}.`);
      return;
    }
    const mode = (req.body as { mode?: unknown } | undefined)?.mode ?? "merge";
    if (mode !== "merge" && mode !== "replace") {
      sendError(res, 400, "Bad Request", 'mode must be "merge" or "replace".');
      return;
    }
    // Installed into the workspace selected in the dashboard (default = rules.json).
    const ws = requireWorkspace(ctx, req, res);
    if (!ws) return;
    try {
      const result = applyPreset(ctx.workspaces.rules(ws.id), preset, mode);
      await ctx.workspaces.saveRules(ws.id, result.rules);
      res.json({ success: true, preset: preset.id, mode, workspace: ws.slug, added: result.added, replaced: result.replaced, rules: result.rules });
    } catch (err) {
      sendInternalError(res, "Failed to apply policy pack", err, "Could not save the rules.");
    }
  });

  router.get("/setup", (req: AuthenticatedRequest, res: Response) => {
    try {
      res.json(snapshot(req.user?.role === "admin"));
    } catch (err) {
      sendInternalError(res, "Setup error", err, "Could not load the gateway setup.");
    }
  });

  router.post("/setup", async (req: AuthenticatedRequest, res: Response) => {
    if (req.user?.role !== "admin") {
      sendError(res, 403, "Forbidden", "Only administrators can change the gateway setup.");
      return;
    }
    const body = req.body as unknown;
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      sendError(res, 400, "Bad Request", "Body must be a JSON object.");
      return;
    }
    const input = body as {
      targetUrl?: unknown;
      rateLimitPerMinute?: unknown;
      listenPort?: unknown;
      publicBaseUrl?: unknown;
      notifications?: {
        slack?: {
          enabled?: unknown;
          mode?: unknown;
          webhookUrl?: unknown;
          botToken?: unknown;
          appToken?: unknown;
          channelId?: unknown;
          approverIds?: unknown;
        };
        telegram?: { enabled?: unknown; mode?: unknown; botToken?: unknown; chatId?: unknown; approverIds?: unknown };
        webhook?: { enabled?: unknown; url?: unknown; secret?: unknown };
      };
      rollback?: { url?: unknown; secret?: unknown };
      privacy?: { redactEmails?: unknown; redactPhones?: unknown };
      timezone?: unknown;
      schedule?: { enabled?: unknown; days?: unknown; start?: unknown; end?: unknown };
      alerts?: { enabled?: unknown; burstThreshold?: unknown; burstWindowMinutes?: unknown; digestHour?: unknown };
      responseGuard?: unknown;
    };

    const cfg = configStore.load();
    const nextCfg = { ...cfg };
    const next = settings.get();
    const fail = (message: string): void => sendError(res, 400, "Bad Request", message);

    // ---- config.json fields ----
    if (input.targetUrl !== undefined) {
      if (typeof input.targetUrl !== "string") return fail("targetUrl must be a string.");
      const parsed = parseTargetUrl(input.targetUrl, port);
      if (!parsed.ok) return fail(parsed.message);
      nextCfg.targetUrl = parsed.url;
    }
    if (input.rateLimitPerMinute !== undefined) {
      const n = input.rateLimitPerMinute;
      if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 1_000_000) {
        return fail("rateLimitPerMinute must be a whole number from 1 to 1,000,000.");
      }
      nextCfg.rateLimitPerMinute = n;
    }

    // ---- SQLite settings ----
    if (input.listenPort !== undefined) {
      const p = input.listenPort;
      if (p !== null && (typeof p !== "number" || !Number.isInteger(p) || p < 1 || p > 65535)) {
        return fail("listenPort must be null or a whole number from 1 to 65535.");
      }
      next.listenPort = p as number | null;
    }
    if (input.publicBaseUrl !== undefined) {
      const c = checkPublicBaseUrl(input.publicBaseUrl);
      if (!c.ok) return fail(c.message);
      next.publicBaseUrl = c.value;
    }

    const n = input.notifications;
    if (n !== undefined) {
      if (typeof n !== "object" || n === null) return fail("notifications must be an object.");
      if (n.slack) {
        if (n.slack.enabled !== undefined) {
          if (typeof n.slack.enabled !== "boolean") return fail("notifications.slack.enabled must be true or false.");
          next.notifications.slack.enabled = n.slack.enabled;
        }
        if (n.slack.webhookUrl !== undefined) {
          const url = typeof n.slack.webhookUrl === "string" ? n.slack.webhookUrl.trim() : null;
          if (url === null || (url !== "" && !url.startsWith(SLACK_PREFIX)) || url.length > 500) {
            return fail(`The Slack webhook URL must start with ${SLACK_PREFIX}`);
          }
          next.notifications.slack.webhookUrl = url;
        }
        if (n.slack.mode !== undefined) {
          if (n.slack.mode !== "webhook" && n.slack.mode !== "socket") return fail('notifications.slack.mode must be "webhook" or "socket".');
          next.notifications.slack.mode = n.slack.mode;
        }
        if (n.slack.botToken !== undefined) {
          const t = typeof n.slack.botToken === "string" ? n.slack.botToken.trim() : null;
          if (t === null || (t !== "" && !SLACK_BOT_TOKEN.test(t))) return fail("The Slack bot token must start with xoxb-.");
          next.notifications.slack.botToken = t;
        }
        if (n.slack.appToken !== undefined) {
          const t = typeof n.slack.appToken === "string" ? n.slack.appToken.trim() : null;
          if (t === null || (t !== "" && !SLACK_APP_TOKEN.test(t))) return fail("The Slack app-level token must start with xapp-.");
          next.notifications.slack.appToken = t;
        }
        if (n.slack.channelId !== undefined) {
          const c = typeof n.slack.channelId === "string" ? n.slack.channelId.trim() : null;
          if (c === null || (c !== "" && !SLACK_CHANNEL.test(c))) return fail("The Slack channel id looks like C0123ABCD (copy it from the channel's details).");
          next.notifications.slack.channelId = c;
        }
        if (n.slack.approverIds !== undefined) {
          const a = checkApprovers(n.slack.approverIds, SLACK_USER, "Slack approver ids look like U0123ABCD, separated by commas.");
          if (!a.ok) return fail(a.message);
          next.notifications.slack.approverIds = a.value;
        }
      }
      if (n.telegram) {
        if (n.telegram.enabled !== undefined) {
          if (typeof n.telegram.enabled !== "boolean") return fail("notifications.telegram.enabled must be true or false.");
          next.notifications.telegram.enabled = n.telegram.enabled;
        }
        if (n.telegram.botToken !== undefined) {
          const t = typeof n.telegram.botToken === "string" ? n.telegram.botToken.trim() : null;
          if (t === null || (t !== "" && !TELEGRAM_TOKEN.test(t))) return fail("The Telegram bot token looks wrong (expected 123456789:ABC...).");
          next.notifications.telegram.botToken = t;
        }
        if (n.telegram.chatId !== undefined) {
          const c = typeof n.telegram.chatId === "string" ? n.telegram.chatId.trim() : null;
          if (c === null || (c !== "" && !TELEGRAM_CHAT.test(c))) return fail("The Telegram chat id must be a number (e.g. -1001234567890) or @channelname.");
          next.notifications.telegram.chatId = c;
        }
        if (n.telegram.mode !== undefined) {
          if (n.telegram.mode !== "polling" && n.telegram.mode !== "links") return fail('notifications.telegram.mode must be "polling" or "links".');
          next.notifications.telegram.mode = n.telegram.mode;
        }
        if (n.telegram.approverIds !== undefined) {
          const a = checkApprovers(n.telegram.approverIds, /^\d{1,15}$/, "Telegram approver ids are numeric user ids, separated by commas.");
          if (!a.ok) return fail(a.message);
          next.notifications.telegram.approverIds = a.value;
        }
      }
      if (n.webhook) {
        if (n.webhook.enabled !== undefined) {
          if (typeof n.webhook.enabled !== "boolean") return fail("notifications.webhook.enabled must be true or false.");
          next.notifications.webhook.enabled = n.webhook.enabled;
        }
        if (n.webhook.url !== undefined) {
          if (typeof n.webhook.url !== "string") return fail("notifications.webhook.url must be a string.");
          const parsed = parseTargetUrl(n.webhook.url, port);
          if (!parsed.ok) return fail(`Webhook URL: ${parsed.message.replace(/^targetUrl/, "The URL")}`);
          next.notifications.webhook.url = parsed.url;
        }
        if (n.webhook.secret !== undefined) {
          const s = checkSecret(n.webhook.secret, "notifications.webhook.secret");
          if (!s.ok) return fail(s.message);
          next.notifications.webhook.secret = s.value;
        }
      }
    }

    if (input.rollback !== undefined) {
      if (typeof input.rollback !== "object" || input.rollback === null) return fail("rollback must be an object.");
      if (input.rollback.url !== undefined) {
        if (typeof input.rollback.url !== "string") return fail("rollback.url must be a string.");
        const parsed = parseTargetUrl(input.rollback.url, port);
        if (!parsed.ok) return fail(`Rollback URL: ${parsed.message.replace(/^targetUrl/, "The URL")}`);
        next.rollback.url = parsed.url;
      }
      if (input.rollback.secret !== undefined) {
        const s = checkSecret(input.rollback.secret, "rollback.secret");
        if (!s.ok) return fail(s.message);
        next.rollback.secret = s.value;
      }
    }

    if (input.privacy !== undefined) {
      if (typeof input.privacy !== "object" || input.privacy === null) return fail("privacy must be an object.");
      for (const k of ["redactEmails", "redactPhones"] as const) {
        const v = input.privacy[k];
        if (v === undefined) continue;
        if (typeof v !== "boolean") return fail(`privacy.${k} must be true or false.`);
        next.privacy[k] = v;
      }
    }

    if (input.timezone !== undefined) {
      if (!isValidTimeZone(input.timezone)) return fail('timezone must be an IANA time zone such as "Europe/London" or "America/New_York".');
      next.timezone = input.timezone;
    }

    if (input.schedule !== undefined) {
      const sc = input.schedule;
      if (typeof sc !== "object" || sc === null) return fail("schedule must be an object.");
      if (sc.enabled !== undefined) {
        if (typeof sc.enabled !== "boolean") return fail("schedule.enabled must be true or false.");
        next.schedule.enabled = sc.enabled;
      }
      if (sc.days !== undefined) {
        if (!Array.isArray(sc.days) || !sc.days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6)) {
          return fail("schedule.days must be a list of weekdays 0-6 (0 = Sunday).");
        }
        next.schedule.days = [...new Set(sc.days as number[])].sort();
      }
      for (const k of ["start", "end"] as const) {
        if (sc[k] === undefined) continue;
        if (typeof sc[k] !== "string" || !HHMM.test(sc[k] as string)) return fail(`schedule.${k} must be a time like "09:00".`);
        next.schedule[k] = sc[k] as string;
      }
      if (next.schedule.enabled && next.schedule.days.length === 0) return fail("Pick at least one business day, or turn business hours off.");
    }

    if (input.alerts !== undefined) {
      const al = input.alerts;
      if (typeof al !== "object" || al === null) return fail("alerts must be an object.");
      if (al.enabled !== undefined) {
        if (typeof al.enabled !== "boolean") return fail("alerts.enabled must be true or false.");
        next.alerts.enabled = al.enabled;
      }
      if (al.burstThreshold !== undefined) {
        if (!Number.isInteger(al.burstThreshold) || (al.burstThreshold as number) < 1 || (al.burstThreshold as number) > 100_000) {
          return fail("alerts.burstThreshold must be a whole number from 1 to 100000.");
        }
        next.alerts.burstThreshold = al.burstThreshold as number;
      }
      if (al.burstWindowMinutes !== undefined) {
        if (!Number.isInteger(al.burstWindowMinutes) || (al.burstWindowMinutes as number) < 1 || (al.burstWindowMinutes as number) > 1440) {
          return fail("alerts.burstWindowMinutes must be a whole number from 1 to 1440.");
        }
        next.alerts.burstWindowMinutes = al.burstWindowMinutes as number;
      }
      if (al.digestHour !== undefined) {
        if (al.digestHour !== null && (!Number.isInteger(al.digestHour) || (al.digestHour as number) < 0 || (al.digestHour as number) > 23)) {
          return fail("alerts.digestHour must be null (off) or an hour 0-23.");
        }
        next.alerts.digestHour = al.digestHour as number | null;
      }
    }

    if (input.responseGuard !== undefined) {
      const rg = validateResponseGuard(input.responseGuard, next.responseGuard);
      if (!rg.ok) return fail(rg.message);
      next.responseGuard = rg.value;
    }

    // Receivers should always be able to verify what the gateway sends them.
    if (next.notifications.webhook.enabled && next.notifications.webhook.url && !next.notifications.webhook.secret) {
      next.notifications.webhook.secret = randomHex(24);
    }
    if (next.rollback.url && !next.rollback.secret) next.rollback.secret = randomHex(24);

    const warnings: string[] = [];
    const { slack: sl, telegram: tgs, webhook: wh } = next.notifications;
    // Only the link-based channels need a Public URL; Telegram polling and Slack Socket Mode do not.
    const linkChannels = [
      sl.enabled && sl.mode === "webhook" && sl.webhookUrl ? "Slack (webhook mode)" : null,
      tgs.enabled && tgs.mode === "links" && tgs.botToken && tgs.chatId ? "Telegram (links mode)" : null,
      wh.enabled && wh.url ? "the custom webhook" : null,
    ].filter(Boolean);
    if (linkChannels.length > 0 && !next.publicBaseUrl) {
      warnings.push(
        `${linkChannels.join(", ")} will not include one-tap Approve / Reject links because no Public URL is set. ` +
          "Telegram polling mode and Slack Socket Mode work without one."
      );
    }
    if (tgs.enabled && tgs.mode === "polling" && (!tgs.botToken || !tgs.chatId)) warnings.push("Telegram polling needs both a bot token and a chat id.");
    if (sl.enabled && sl.mode === "socket" && (!sl.botToken || !sl.appToken || !sl.channelId)) {
      warnings.push("Slack Socket Mode needs a bot token (xoxb-), an app-level token (xapp-) and a channel id.");
    }
    if ((tgs.enabled && !tgs.approverIds) || (sl.enabled && sl.mode === "socket" && !sl.approverIds)) {
      warnings.push("No approver ids are set, so anyone in the chat / channel can approve. Add your user id to restrict it.");
    }
    const features = ctx.license.current().features;
    if (!features.interactiveApprovals && ((tgs.enabled && tgs.mode === "polling") || (sl.enabled && sl.mode === "socket"))) {
      warnings.push(
        "Zero-tunnel Telegram polling / Slack Socket Mode buttons need a Mont Pro or Agency license. Notifications are still sent; approve in the dashboard (or via signed links when a Public URL is set)."
      );
    }
    if (next.rollback.url && !features.rollbackWebhooks) {
      warnings.push("Compensating rollback webhooks are a Mont Pro feature: the URL is saved but will not be called until a license is active.");
    }
    if (next.responseGuard.enabled && next.responseGuard.onLargeArray === "block") {
      warnings.push(`Responses with any JSON array longer than ${next.responseGuard.maxArrayItems} items will now be withheld (502). Raise the limit if a legitimate endpoint returns long lists.`);
    }
    if (next.publicBaseUrl.startsWith("http://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(next.publicBaseUrl)) {
      warnings.push("The Public URL uses plain http://. Approval links should travel over https://.");
    }
    if (input.listenPort !== undefined && next.listenPort !== null && next.listenPort !== port) {
      warnings.push(`The proxy keeps listening on port ${port} until it is restarted; it will use port ${next.listenPort} next time.`);
    }

    try {
      if (nextCfg.targetUrl !== cfg.targetUrl || nextCfg.rateLimitPerMinute !== cfg.rateLimitPerMinute) configStore.save(nextCfg);
      await settings.save(next);
      res.json({ success: true, ...snapshot(true), warnings });
    } catch (err) {
      sendInternalError(res, "Failed to save setup", err, "Could not save the gateway setup.");
    }
  });

  router.post("/setup/test-notification", async (req: AuthenticatedRequest, res: Response) => {
    if (req.user?.role !== "admin") {
      sendError(res, 403, "Forbidden", "Only administrators can send test notifications.");
      return;
    }
    try {
      const results = await notifier.sendTest();
      if (results.length === 0) {
        sendError(res, 400, "Bad Request", "No notification channel is enabled and fully configured.");
        return;
      }
      res.json({ success: results.every((r) => r.ok), results });
    } catch (err) {
      sendInternalError(res, "Test notification error", err, "Could not send the test notification.");
    }
  });
}
