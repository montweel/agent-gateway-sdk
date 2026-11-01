import express from "express";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { GatewayContext } from "./context";
import type { LogStatus, Rule } from "./types";
import {
  HOPS_HEADER,
  JSON_BODY_LIMIT,
  MAX_HOPS,
  MAX_LOG_PATH_LENGTH,
  MAX_LOG_UA_LENGTH,
  MAX_PENDING_ACTIONS,
  MAX_PENDING_BODY_BYTES,
  MAX_PENDING_DISPLAY_CHARS,
  PENDING_TTL_MS,
  REPLAY_HEADER,
} from "./constants";
import { encryptPayload, safeEqualStrings } from "./crypto";
import { proxyToTarget } from "./proxy";
import {
  extractBody,
  extractRedactedBody,
  normalizePath,
  redactQueryString,
  sanitizeHeaders,
  sendCaughtError,
  sendError,
  truncate,
} from "./utils";

/**
 * Builds the interceptor that guards every /api/* request.
 *
 * Order, cheapest and least trusting first:
 *   1. loop guard            (x-gateway-hops)
 *   2. IP rate limit         (before any body is read or parsed)
 *   3. agent API key         (401 when required and missing/invalid)
 *   4. JSON body parsing     (1 MB cap)
 *   5. rule lookup           (default deny) -> block / queue for approval / allow
 */
export function createInterceptor(ctx: GatewayContext): RequestHandler {
  async function logRequest(
    method: string,
    reqPath: string,
    status: LogStatus,
    userAgent: string,
    agentKey: string | null
  ): Promise<void> {
    try {
      await ctx.db.run(
        `INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          new Date().toISOString(),
          method,
          truncate(reqPath, MAX_LOG_PATH_LENGTH),
          status,
          truncate(userAgent, MAX_LOG_UA_LENGTH),
          agentKey,
        ]
      );
    } catch (err) {
      console.error("Failed to write log:", err);
    }
  }

  const cleanPathOf = (req: Request): string => normalizePath(req.originalUrl.split("?")[0]);
  const userAgentOf = (req: Request): string => req.get("user-agent") ?? "unknown";

  /** Rule enforcement for a request whose body is already parsed. */
  async function handle(
    req: Request,
    res: Response,
    next: NextFunction,
    agentKeyName: string | null,
    isReplay: boolean
  ): Promise<void> {
    try {
      await ctx.ready;
      const config = ctx.config.load();

      // Internal replay of an approved request: already authorised by a human.
      if (isReplay) {
        if (config.targetUrl) await proxyToTarget(req, res, config.targetUrl, config);
        else next();
        return;
      }

      const cleanPath = cleanPathOf(req);
      const userAgent = userAgentOf(req);

      // Rule lookup (DEFAULT DENY: unlisted = BLOCK). "<METHOD> <path>" wins over
      // "<path>". Exact match only, so the path that was approved is
      // byte-for-byte the path forwarded upstream.
      const rule: Rule = ctx.rules.lookup(req.method, cleanPath) ?? { mode: "BLOCK", description: "" };

      if (rule.mode === "BLOCK") {
        await logRequest(req.method, cleanPath, "BLOCKED", userAgent, agentKeyName);
        res.status(403).json({
          error: "Forbidden",
          message: `Access to ${cleanPath} is blocked by gateway rules.`,
          path: cleanPath,
        });
        return;
      }

      if (rule.mode === "REQUIRE_APPROVAL") {
        const pending = await ctx.db.get<{ count: number }>(
          "SELECT COUNT(*) as count FROM pending_actions WHERE status = 'PENDING'"
        );
        if ((pending?.count ?? 0) >= MAX_PENDING_ACTIONS) {
          await logRequest(req.method, cleanPath, "BLOCKED", userAgent, agentKeyName);
          res.setHeader("Retry-After", "60");
          sendError(res, 503, "Service Unavailable", "The approval queue is full. Try again later.");
          return;
        }

        // Queued requests are stored (encrypted and redacted) until decided, so cap
        // their size: otherwise 1,000 queued 1 MB bodies would fill the disk.
        const originalBody = extractBody(req);
        if (originalBody !== null && Buffer.byteLength(originalBody) > MAX_PENDING_BODY_BYTES) {
          await logRequest(req.method, cleanPath, "BLOCKED", userAgent, agentKeyName);
          sendError(
            res,
            413,
            "Payload Too Large",
            `Requests that need approval can have a body of at most ${MAX_PENDING_BODY_BYTES / 1024} KB.`
          );
          return;
        }

        // What the approver sees (and what logs/UI keep) has secrets removed. What
        // is replayed on approval is the original request, stored only in encrypted
        // form and wiped as soon as the action is decided or expires.
        const encryptedPayload = encryptPayload(
          JSON.stringify({ path: req.originalUrl, body: originalBody }),
          ctx.config.replayEncryptionKey()
        );
        const redactedBody = extractRedactedBody(req);
        const displayBody =
          redactedBody !== null && redactedBody.length > MAX_PENDING_DISPLAY_CHARS
            ? `${redactedBody.slice(0, MAX_PENDING_DISPLAY_CHARS)}… [truncated]`
            : redactedBody;

        const inserted = await ctx.db.run(
          `INSERT INTO pending_actions
             (timestamp, method, path, headers, body, status, expires_at, agent_key, encrypted_payload)
           VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)`,
          [
            new Date().toISOString(),
            req.method,
            truncate(redactQueryString(req.originalUrl), MAX_LOG_PATH_LENGTH),
            JSON.stringify(sanitizeHeaders(req)),
            displayBody,
            Date.now() + PENDING_TTL_MS,
            agentKeyName,
            encryptedPayload,
          ]
        );
        await logRequest(req.method, cleanPath, "QUEUED", userAgent, agentKeyName);
        res.status(202).json({
          status: "PENDING_APPROVAL",
          approvalId: inserted.lastID,
          message: "Request queued for human admin approval.",
        });
        return;
      }

      // ALLOW
      await logRequest(req.method, cleanPath, "ALLOWED", userAgent, agentKeyName);
      if (config.targetUrl) await proxyToTarget(req, res, config.targetUrl, config);
      else next();
    } catch (err) {
      console.error("Gateway error:", err);
      if (!res.headersSent) {
        sendError(res, 500, "Internal Server Error", "The gateway hit an unexpected error.");
      }
    }
  }

  const parseJson = express.json({ limit: JSON_BODY_LIMIT });

  return (req, res, next) => {
    void (async () => {
      try {
        // 1. Loop guard: a target that points back at a gateway would recurse forever.
        const hops = Number.parseInt(req.get(HOPS_HEADER) ?? "0", 10);
        if (Number.isFinite(hops) && hops >= MAX_HOPS) {
          sendError(res, 508, "Loop Detected", "Too many gateway hops. Check that targetUrl does not point back at a gateway.");
          return;
        }

        const replayHeader = req.get(REPLAY_HEADER);
        const isReplay = Boolean(replayHeader && safeEqualStrings(replayHeader, ctx.replaySecret));

        let agentKeyName: string | null = null;
        if (!isReplay) {
          const config = ctx.config.load();
          const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";

          // 2. Rate limit BEFORE parsing the body, so a flood costs almost nothing.
          // A matched rule with its own rateLimit gets a separate "<ip>:<rule key>" bucket;
          // everything else (no rule, or no custom limit) uses the global bucket.
          const matched = ctx.rules.lookupEntry(req.method, cleanPathOf(req));
          const ruleLimit = matched?.rule.rateLimit;
          const customLimit = typeof ruleLimit === "number" && ruleLimit > 0 ? ruleLimit : null;
          const effectiveLimit = customLimit ?? config.rateLimitPerMinute;
          const rate = customLimit
            ? ctx.limiters.checkRateLimit(ip, customLimit, matched!.key)
            : ctx.limiters.checkRateLimit(ip, config.rateLimitPerMinute);
          if (rate.limited) {
            // One log row per client per window, not one per rejected request.
            if (rate.firstLimited) {
              await ctx.ready;
              await logRequest(req.method, cleanPathOf(req), "RATE_LIMITED", userAgentOf(req), null);
            }
            res.setHeader("Retry-After", String(rate.retryAfterSec));
            res.status(429).json({
              error: "Too Many Requests",
              message: `Rate limit of ${effectiveLimit} requests per minute exceeded.`,
              retryAfterSeconds: rate.retryAfterSec,
            });
            return;
          }

          // 3. Agent API key. Optional unless requireAgentApiKey is on.
          const rawKey = ctx.agentKeys.extract(req);
          if (rawKey || config.requireAgentApiKey) {
            await ctx.ready;
            const info = rawKey ? await ctx.agentKeys.verify(rawKey) : null;
            if (info) {
              agentKeyName = info.name;
            } else if (config.requireAgentApiKey) {
              await logRequest(req.method, cleanPathOf(req), "BLOCKED", userAgentOf(req), null);
              res.setHeader("WWW-Authenticate", 'Bearer realm="agent-gateway"');
              sendError(
                res,
                401,
                "Unauthorized",
                "A valid agent API key is required. Send it as x-agent-key or Authorization: Bearer agk_..."
              );
              return;
            }
          }
        }

        // 4. Body parsing (only for requests that passed the checks above)
        parseJson(req, res, (err?: unknown) => {
          if (err) {
            sendCaughtError(res, err);
            return;
          }
          void handle(req, res, next, agentKeyName, isReplay);
        });
      } catch (err) {
        console.error("Gateway error:", err);
        if (!res.headersSent) {
          sendError(res, 500, "Internal Server Error", "The gateway hit an unexpected error.");
        }
      }
    })();
  };
}
