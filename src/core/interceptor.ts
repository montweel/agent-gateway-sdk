import express from "express";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { GatewayContext } from "./context";
import type { Rule } from "./types";
import {
  AGENT_KEY_HEADER,
  AGENT_KEY_PREFIX,
  AGENT_REASON_HEADER,
  HOPS_HEADER,
  JSON_BODY_LIMIT,
  MAX_AGENT_REASON_LENGTH,
  MAX_HOPS,
  MAX_UPSTREAM_BYTES,
  REPLAY_HEADER,
  WORKSPACE_HEADER,
  WORKSPACE_KEY_PREFIX,
} from "./constants";
import { safeEqualStrings } from "./crypto";
import { evaluateRule, policiesReadBody, splitShadow } from "./policy";
import type { PolicyDecision } from "./policy";
import { proxyToTarget } from "./proxy";
import type { InspectOutcome } from "./proxy";
import { bucketIp } from "./rateLimit";
import { buildSnapshot, createAudit, discardPending, queuePending } from "./pendingQueue";
import type { Audit, Caller } from "./pendingQueue";
import { applyOperatingMode } from "./operatingMode";
import { callerIdOf, extractAmount } from "./guards";
import { extractBody, failClosed, normalizePath, sendCaughtError, sendError, truncate, withTimeout } from "./utils";
import { resolveWorkspace, scopedRuleKey, splitWorkspacePath } from "./workspaces";
import type { Workspace } from "./workspaces";
import { describeFindings, inspectResponseBody } from "./responseGuard";

/** Cleans the free-text justification an agent may send in x-agent-reason. */
export function cleanAgentReason(raw: string | undefined | null): string | null {
  if (!raw) return null;
  // eslint-disable-next-line no-control-regex
  const clean = raw.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return clean ? truncate(clean, MAX_AGENT_REASON_LENGTH) : null;
}

/** What an agent is told when it is refused. Thresholds stay private; the kind of refusal does not. */
export function blockMessage(matched: string, path: string, reason: string | null): string {
  if (matched === "lockdown") return "The gateway is in emergency lockdown: no agent requests are being accepted right now.";
  if (matched === "duplicate") return `Refused: this looks like a duplicate of an action already sent. ${reason ?? ""}`.trim();
  if (matched === "budget") return "Refused: the spending budget for this action has been reached.";
  if (matched.startsWith("tier:")) return `This request to ${path} is blocked by a gateway payload policy.`;
  return `Access to ${path} is blocked by gateway rules.`;
}

/** Splits a raw credential into an agent key (agk_) and a workspace key (mws_). */
export function splitCredentials(req: Request): { agentKey: string | null; workspaceKey: string | null } {
  const header = req.get(AGENT_KEY_HEADER)?.trim() || null;
  const auth = req.get("authorization")?.trim();
  const bearer = auth && auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : null;
  let agentKey: string | null = null;
  let workspaceKey: string | null = null;
  for (const v of [header, bearer]) {
    if (!v) continue;
    if (v.startsWith(WORKSPACE_KEY_PREFIX)) workspaceKey ??= v;
    else if (v === header || v.startsWith(AGENT_KEY_PREFIX)) agentKey ??= v;
  }
  return { agentKey, workspaceKey };
}

/** Everything the workspace decides for one request. */
interface Scope {
  workspace: Workspace;
  /** Path (no query) rules are matched against, workspace prefix removed. */
  cleanPath: string;
  /** Path + query forwarded upstream / queued for replay, workspace prefix removed. */
  forwardUrl: string;
}

/**
 * Builds the interceptor that guards every /api/* request.
 *
 * Order, cheapest and least trusting first:
 *   1. loop guard            (x-gateway-hops)
 *   2. workspace             (path prefix / x-mont-workspace / mws_ key; license entitlement)
 *   3. rate limit            (before any body is read or parsed)
 *   4. agent API key         (401 when required and missing/invalid)
 *   5. kill-switch           (403 for blocked agent keys / IPs)
 *   6. JSON body parsing     (1 MB cap)
 *   7. rule + payload policy (default deny) -> shadow / operating mode / budgets & dedupe
 *                            -> block / queue for approval / allow
 *   8. response guard        (optional: bulk-dump and secret breaker on what comes back)
 *
 * FAIL-CLOSED CONTRACT. A request is forwarded (next() or the upstream proxy) only after
 * every step above succeeded AND its ALLOWED audit row is durably written. Any thrown
 * error, rejected promise, SQLite error, SQLite lock wait longer than ctx.dbTimeoutMs,
 * policy evaluation error or client disconnect ends the request with 4xx/503 (or a
 * destroyed socket) and nothing is forwarded. There is no code path that calls next()
 * from an error handler.
 */
export function createInterceptor(ctx: GatewayContext): RequestHandler {
  const timed = <T>(p: Promise<T>, label: string): Promise<T> => withTimeout(p, ctx.dbTimeoutMs, label);
  const audit = createAudit(ctx);

  const userAgentOf = (req: Request): string => req.get("user-agent") ?? "unknown";
  // Note: req.destroyed turns true as soon as the body has been read, so the socket is what tells
  // us whether the agent is still there.
  const clientGone = (req: Request, res: Response): boolean =>
    Boolean(req.socket?.destroyed) || res.destroyed || res.headersSent || res.writableEnded;

  /** Body bytes were declared but express.json did not parse them (not application/json). */
  function hasUnparsedBody(req: Request): boolean {
    const te = req.headers["transfer-encoding"];
    const len = Number(req.headers["content-length"] ?? "0");
    const declared = te !== undefined || (Number.isFinite(len) && len > 0);
    return declared && !req.is("application/json");
  }

  /** Response guard verdict -> audit row + what the client gets. */
  function responseInspector(scope: Scope, method: string, caller: Caller | null, userAgent: string) {
    return async (_status: number, contentType: string | null, body: Buffer): Promise<InspectOutcome> => {
      const settings = ctx.settings.peek().responseGuard;
      const verdict = inspectResponseBody(contentType, body, settings);
      if (verdict.action === "pass") return { action: "pass" };
      const summary = describeFindings(verdict.findings);
      if (verdict.action === "block") {
        await audit.logRefusal({ method, path: scope.cleanPath, status: "RESPONSE_BLOCKED", caller, userAgent, detail: `response withheld: ${summary}`, workspaceId: scope.workspace.id });
        return {
          action: "block",
          message: `Response Policy Violation: the upstream response contained ${summary}, so it was withheld.`,
          violations: verdict.findings,
        };
      }
      await audit.logRefusal({ method, path: scope.cleanPath, status: "RESPONSE_SCRUBBED", caller, userAgent, detail: `response scrubbed: ${summary}`, workspaceId: scope.workspace.id });
      return { action: "modified", body: verdict.body };
    };
  }

  /**
   * Middleware mode (no upstream URL): the host app writes the response. With the response guard
   * on, its bytes are buffered (up to the upstream cap) and inspected before anything is sent.
   * Event streams pass through untouched.
   */
  function guardHostResponse(res: Response, inspect: (status: number, ct: string | null, body: Buffer) => Promise<InspectOutcome>): void {
    const origWrite = res.write.bind(res) as (...a: unknown[]) => boolean;
    const origEnd = res.end.bind(res) as (...a: unknown[]) => Response;
    const chunks: Buffer[] = [];
    let size = 0;
    let overflow = false;
    let passthrough = false;
    const restore = (): void => {
      res.write = origWrite as unknown as Response["write"];
      res.end = origEnd as unknown as Response["end"];
    };
    const toBuffer = (chunk: unknown, encoding: unknown): Buffer | null => {
      if (chunk === undefined || chunk === null || typeof chunk === "function") return null;
      if (Buffer.isBuffer(chunk)) return chunk;
      if (chunk instanceof Uint8Array) return Buffer.from(chunk);
      return Buffer.from(String(chunk), typeof encoding === "string" ? (encoding as BufferEncoding) : "utf8");
    };
    const isStream = (): boolean => /event-stream/i.test(String(res.getHeader("content-type") ?? ""));

    res.write = ((chunk: unknown, encoding?: unknown, cb?: unknown) => {
      if (passthrough || (chunks.length === 0 && isStream())) {
        passthrough = true;
        restore();
        return origWrite(chunk, encoding, cb);
      }
      const b = toBuffer(chunk, encoding);
      if (b) {
        size += b.length;
        if (size > MAX_UPSTREAM_BYTES) overflow = true;
        else chunks.push(b);
      }
      const callback = typeof encoding === "function" ? encoding : cb;
      if (typeof callback === "function") process.nextTick(callback as () => void);
      return true;
    }) as Response["write"];

    res.end = ((chunk?: unknown, encoding?: unknown, cb?: unknown) => {
      if (passthrough) return origEnd(chunk, encoding, cb);
      const b = toBuffer(chunk, encoding);
      if (b) {
        size += b.length;
        if (size > MAX_UPSTREAM_BYTES) overflow = true;
        else chunks.push(b);
      }
      const callback = typeof chunk === "function" ? chunk : typeof encoding === "function" ? encoding : cb;
      restore();
      const finish = (status: number | null, body: Buffer, extraHeaders: Record<string, string> = {}): void => {
        if (status !== null) res.statusCode = status;
        for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
        if (!res.headersSent) res.setHeader("content-length", String(body.length));
        origEnd(body, typeof callback === "function" ? callback : undefined);
      };
      if (overflow) {
        res.removeHeader("etag");
        res.setHeader("content-type", "application/json; charset=utf-8");
        finish(502, Buffer.from(JSON.stringify({ error: "Response Policy Violation", message: "The response was too large for the response guard to inspect, so it was withheld." })));
        return res;
      }
      const body = Buffer.concat(chunks);
      inspect(res.statusCode, (res.getHeader("content-type") as string | undefined) ?? null, body).then(
        (outcome) => {
          if (outcome.action === "pass") return finish(null, body);
          res.removeHeader("etag");
          if (outcome.action === "modified") return finish(null, outcome.body, { "x-mont-response-guard": "scrubbed" });
          res.setHeader("content-type", "application/json; charset=utf-8");
          finish(502, Buffer.from(JSON.stringify({ error: "Response Policy Violation", message: outcome.message, violations: outcome.violations })), {
            "x-mont-response-guard": "blocked",
          });
        },
        (err: unknown) => {
          console.error("[agent-gateway] FAIL-CLOSED (response guard):", err);
          res.removeHeader("etag");
          res.setHeader("content-type", "application/json; charset=utf-8");
          finish(502, Buffer.from(JSON.stringify({ error: "Response Policy Violation", message: "The response could not be inspected, so it was withheld." })));
        }
      );
      return res;
    }) as Response["end"];
  }

  /** Hands the request on exactly once, and never to a client that has already gone away. */
  async function forward(req: Request, res: Response, next: NextFunction, scope: Scope, caller: Caller | null): Promise<void> {
    if (clientGone(req, res)) return;
    const config = ctx.config.load();
    const upstream = scope.workspace.upstreamUrl ?? config.targetUrl;
    // Replays (caller null) answer the human approver, not the agent: not guarded.
    const guardOn = caller !== null && ctx.settings.peek().responseGuard.enabled;
    const inspect = guardOn ? responseInspector(scope, req.method, caller, caller?.userAgent ?? userAgentOf(req)) : undefined;
    if (upstream) {
      await proxyToTarget(req, res, upstream, config, { forwardUrl: scope.forwardUrl, inspectResponse: inspect });
      return;
    }
    // Middleware mode: the host app behind the gateway sees the path without the workspace prefix.
    if (scope.forwardUrl !== req.originalUrl) {
      const prefix = req.originalUrl.slice(0, req.originalUrl.length - req.url.length); // the mount path ("/api")
      if (scope.forwardUrl.startsWith(prefix)) req.url = scope.forwardUrl.slice(prefix.length) || "/";
    }
    if (inspect) guardHostResponse(res, inspect);
    next();
  }

  /** Rule enforcement for a request whose body is already parsed. */
  async function handle(req: Request, res: Response, next: NextFunction, caller: Caller | null, scope: Scope | null, isReplay: boolean): Promise<void> {
    try {
      // Internal replay of an approved request: already authorised by a human.
      if (isReplay) {
        const cleanPath = normalizePath(req.originalUrl.split("?")[0]);
        await forward(req, res, next, { workspace: ctx.workspaces.defaultWorkspace(), cleanPath, forwardUrl: req.originalUrl }, null);
        return;
      }
      if (caller === null || scope === null) throw new Error("Caller identity missing on a non-replay request.");
      const { workspace, cleanPath } = scope;
      const wsId = workspace.id;

      // Rule lookup (DEFAULT DENY: unlisted = BLOCK). Exact keys win over wildcard keys,
      // method-specific over any-method (see rules.ts).
      const entry = ctx.workspaces.lookupEntry(wsId, req.method, cleanPath);
      const rule: Rule = entry?.rule ?? { mode: "BLOCK", description: "" };
      const callerId = callerIdOf(caller);
      const snapshot = (): string => buildSnapshot(ctx, { kind: "http", body: req.body, query: req.query, headers: req.headers, callerId });

      // A policy that reads the body can only be trusted if the body is the JSON we parsed.
      // A text/plain or form body would be invisible to the policy yet still readable by
      // the app behind the gateway, so it is refused rather than waved through.
      if (policiesReadBody(rule) && hasUnparsedBody(req)) {
        await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "non-JSON body on a payload-policy route", workspaceId: wsId });
        sendError(res, 415, "Unsupported Media Type", "This endpoint is guarded by a payload policy and only accepts application/json bodies.");
        return;
      }

      const raw: PolicyDecision = entry ? evaluateRule(rule, { body: req.body, query: req.query, headers: req.headers }) : { mode: "BLOCK", matched: "default-deny" };
      // Shadow ("dry run") rules are enforced as ALLOW; what they would have done is recorded.
      const { decision: ruleDecision, shadow } = splitShadow(raw);
      // Shop-wide / client-wide modes (lockdown, approval-only, business hours) on top of the rule...
      const moded = applyOperatingMode(ctx, ruleDecision, req.method, "http", workspace);
      // ...then cross-request guards (spending budget, duplicate protection), per workspace.
      const guard = await ctx.guards.evaluate(entry ? scopedRuleKey(wsId, entry.key) : null, entry?.rule ?? null, moded, req.body, callerId);
      const amount = extractAmount(req.body);
      try {
        const decision = guard.decision;
        const why = guard.reason ? `${decision.matched}: ${guard.reason}` : decision.matched;

        if (decision.mode === "BLOCK") {
          await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: why, amount, workspaceId: wsId, snapshot: snapshot() });
          res.status(403).json({ error: "Forbidden", message: blockMessage(decision.matched, cleanPath, guard.reason), path: cleanPath });
          return;
        }

        if (decision.mode === "REQUIRE_APPROVAL") {
          const queued = await queuePending(ctx, audit, {
            kind: "http",
            method: req.method,
            originalPath: scope.forwardUrl,
            cleanPath,
            originalBody: extractBody(req),
            query: req.query,
            headers: req.headers,
            caller,
            agentReason: cleanAgentReason(req.get(AGENT_REASON_HEADER)),
            matched: why,
            amount,
            workspace,
            snapshot: snapshot(),
          });
          if (!queued.ok) {
            if (queued.retryAfter) res.setHeader("Retry-After", String(queued.retryAfter));
            sendError(res, queued.status, queued.error, queued.message);
            return;
          }
          try {
            await guard.commit(queued.id);
            guard.release();
          } catch (err) {
            await discardPending(ctx, queued.id, "Discarded: the duplicate-protection record could not be written.").catch(() => undefined);
            throw err;
          }
          // The agent may be gone; the row stays so the admin still sees the attempt.
          if (clientGone(req, res)) return;
          res.status(202).json({
            status: "PENDING_APPROVAL",
            approvalId: queued.id,
            message: "Request queued for human admin approval.",
            ...(workspace.isDefault ? {} : { workspace: workspace.slug }),
            ...(decision.matched !== "rule" && !decision.matched.startsWith("tier:") ? { reason: guard.reason ?? decision.matched } : {}),
          });
          return;
        }

        // ALLOW: the budget / duplicate record and the audit row must be durable BEFORE the
        // request leaves the gateway.
        await guard.commit(null);
        guard.release(); // recorded: the next request on this rule may be checked now
        const shadowNote = shadow ? `shadow: would have ${shadow === "BLOCK" ? "blocked" : "held for approval"} (${ruleDecision.matched})` : null;
        await audit.logStrict({
          method: req.method,
          path: cleanPath,
          status: "ALLOWED",
          caller,
          userAgent: caller.userAgent,
          detail: shadowNote ?? (decision.matched === "rule" ? null : decision.matched),
          amount,
          workspaceId: wsId,
          shadow,
          snapshot: snapshot(),
        });
        await forward(req, res, next, scope, caller);
      } finally {
        guard.release();
      }
    } catch (err) {
      failClosed(res, "rule enforcement", err);
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

        let caller: Caller | null = null;
        let scope: Scope | null = null;
        if (!isReplay) {
          const config = ctx.config.load();
          const rawIp = req.ip ?? req.socket.remoteAddress ?? "unknown";
          const userAgent = userAgentOf(req);

          // Nothing below may run against a database that failed to start (workspaces live there).
          await ctx.ready;

          // 2. Workspace: /api/w/<slug>/..., x-mont-workspace, or the workspace's mws_ key.
          // A path prefix only counts when it names an existing workspace, so a v1.x app's own
          // /api/w/... routes keep working.
          const split = splitWorkspacePath(req.originalUrl);
          const pathWs = split && ctx.workspaces.bySlug(split.slug) ? split : null;
          const creds = splitCredentials(req);
          const resolved = resolveWorkspace(ctx.workspaces, { pathSlug: pathWs?.slug ?? null, headerSlug: req.get(WORKSPACE_HEADER) ?? null, key: creds.workspaceKey });
          const forwardUrl = pathWs ? pathWs.rest : req.originalUrl;
          const cleanPath = normalizePath(forwardUrl.split("?")[0]);
          const anonymous: Caller = { ip: bucketIp(rawIp), userAgent, agentKeyName: null, agentKeyId: null, agentKeyPrefix: null };
          if (!resolved.ok) {
            await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller: anonymous, userAgent, detail: resolved.reason, workspaceId: ctx.workspaces.bySlug(pathWs?.slug ?? req.get(WORKSPACE_HEADER) ?? "")?.id ?? null });
            if (resolved.status === 401) res.setHeader("WWW-Authenticate", 'Bearer realm="agent-gateway"');
            sendError(res, resolved.status, resolved.error, resolved.message);
            return;
          }
          const workspace = resolved.workspace;
          // License: workspaces beyond the plan's limit are refused (never silently unguarded).
          const license = ctx.license.current();
          if (!ctx.workspaces.isEntitled(workspace.id, license.maxWorkspaces)) {
            await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller: anonymous, userAgent, detail: "workspace over the license limit", workspaceId: workspace.id });
            sendError(
              res,
              402,
              "Payment Required",
              `Workspace "${workspace.slug}" is beyond this installation's license (${license.maxWorkspaces} workspace${license.maxWorkspaces === 1 ? "" : "s"} on ${license.tier}). Activate a Mont Agency key to serve it.`
            );
            return;
          }
          scope = { workspace, cleanPath, forwardUrl };

          // 3. Rate limit BEFORE parsing the body, so a flood costs almost nothing.
          // A matched rule with its own rateLimit gets a separate "<ip>:<workspace|rule key>" bucket;
          // everything else (no rule, or no custom limit) uses the global bucket.
          const matched = ctx.workspaces.lookupEntry(workspace.id, req.method, cleanPath);
          const ruleLimit = matched?.rule.rateLimit;
          const customLimit = typeof ruleLimit === "number" && ruleLimit > 0 ? ruleLimit : null;
          const effectiveLimit = customLimit ?? config.rateLimitPerMinute;
          const rate = customLimit
            ? ctx.limiters.checkRateLimit(rawIp, customLimit, scopedRuleKey(workspace.id, matched!.key))
            : ctx.limiters.checkRateLimit(rawIp, config.rateLimitPerMinute);
          if (rate.limited) {
            // One log row per client per window, not one per rejected request.
            if (rate.firstLimited) {
              void audit
                .logRefusal({
                  method: req.method,
                  path: cleanPath,
                  status: "RATE_LIMITED",
                  caller: anonymous,
                  userAgent,
                  workspaceId: workspace.id,
                  snapshot: buildSnapshot(ctx, { kind: "http", body: undefined, bodyUnknown: true, query: req.query, headers: req.headers, callerId: `ip:${anonymous.ip}` }),
                })
                .catch(() => undefined);
            }
            res.setHeader("Retry-After", String(rate.retryAfterSec));
            res.status(429).json({
              error: "Too Many Requests",
              message: `Rate limit of ${effectiveLimit} requests per minute exceeded.`,
              retryAfterSeconds: rate.retryAfterSec,
            });
            return;
          }

          caller = { ...anonymous };

          // 4. Agent API key. Optional unless requireAgentApiKey is on; a workspace's own mws_ key
          // also authenticates the caller for that workspace.
          const rawKey = creds.agentKey;
          if (rawKey || (config.requireAgentApiKey && !resolved.authenticatedByKey)) {
            const info = rawKey ? await timed(ctx.agentKeys.verify(rawKey), "agent key lookup") : null;
            if (info && rawKey) {
              caller.agentKeyName = info.name;
              caller.agentKeyId = info.id;
              caller.agentKeyPrefix = rawKey.slice(0, AGENT_KEY_PREFIX.length + 4);
            } else if (config.requireAgentApiKey && !resolved.authenticatedByKey) {
              await audit.logRefusal({ method: req.method, path: cleanPath, status: "BLOCKED", caller, userAgent, detail: "missing or invalid agent key", workspaceId: workspace.id });
              res.setHeader("WWW-Authenticate", 'Bearer realm="agent-gateway"');
              sendError(res, 401, "Unauthorized", "A valid agent API key is required. Send it as x-agent-key or Authorization: Bearer agk_...");
              return;
            }
          }
          if (resolved.authenticatedByKey && caller.agentKeyName === null) {
            caller.agentKeyName = `workspace:${workspace.slug}`;
          }

          // 5. Kill-switch: callers blocked via "Revoke & Block Caller".
          const blocked = ctx.blocklist.match({ ip: rawIp, agentKeyId: caller.agentKeyId });
          if (blocked) {
            await audit.logRefusal({
              method: req.method,
              path: cleanPath,
              status: "BLOCKED",
              caller,
              userAgent,
              detail: `caller blocked (${blocked.kind}) by ${blocked.created_by}`,
              workspaceId: workspace.id,
            });
            sendError(res, 403, "Forbidden", "This caller has been blocked by a gateway administrator.");
            return;
          }
        } else {
          await ctx.ready;
        }

        // 6. Body parsing (only for requests that passed the checks above)
        parseJson(req, res, (err?: unknown) => {
          if (err) {
            // Malformed JSON, oversized body or bad charset: refused, never forwarded.
            sendCaughtError(res, err);
            return;
          }
          void handle(req, res, next, caller, scope, isReplay);
        });
      } catch (err) {
        failClosed(res, "pre-checks", err);
      }
    })();
  };
}

export type { Audit };
