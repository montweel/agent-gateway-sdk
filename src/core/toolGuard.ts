import type { GatewayContext } from "./context";
import type { Rule } from "./types";
import { AGENT_KEY_PREFIX, MCP_RULE_METHOD, MCP_TOOL_PATH_PREFIX, WORKSPACE_KEY_PREFIX } from "./constants";
import { evaluateRule, splitShadow } from "./policy";
import type { PolicyDecision } from "./policy";
import { bucketIp } from "./rateLimit";
import { buildSnapshot, createAudit, discardPending, queuePending } from "./pendingQueue";
import type { Caller } from "./pendingQueue";
import { withTimeout } from "./utils";
import { applyOperatingMode } from "./operatingMode";
import { callerIdOf, extractAmount } from "./guards";
import { resolveWorkspace, scopedRuleKey } from "./workspaces";
import { decryptPayload } from "./crypto";
import { describeFindings, inspectMcpResult } from "./responseGuard";

/**
 * Guard for MCP `tools/call` (JSON-RPC 2.0). Transport-agnostic: mcpProxy.ts uses it for
 * Streamable HTTP and stdio, and custom transports can call it directly.
 *
 * Mapping onto the existing engine:
 *   rule key   "MCP /api/mcp/tools/<tool name>"   (wildcards work: "MCP /api/mcp/tools/*delete*")
 *   body       params.arguments                   (payload policies: "body.amount", "body.to.email", ...)
 *   caller     IP / agent key / client name       (rate limits, kill-switch, audit)
 *
 * Approval is a gate, not a replay: the transport keeps the original call in memory and runs
 * it only when an approver decides APPROVE (dashboard, phone link, Telegram or Slack button).
 * If the agent disconnects or the wait times out, the action is EXPIRED so it can never run later.
 * Every internal error yields BLOCK (fail closed).
 */

export interface ToolCallRequest {
  toolName: string;
  /** params.arguments */
  arguments: unknown;
  /** agentKey: an agk_ agent key or a workspace's mws_ key. */
  caller: { ip: string; userAgent: string; agentKey?: string | null };
  agentReason?: string | null;
  /** Workspace slug (x-mont-workspace header, /w/<slug>/ mount, or the proxy's --workspace option). */
  workspace?: string | null;
}

export type GuardResult =
  | { decision: "ALLOW"; ruleKey: string; workspaceId: number }
  | { decision: "BLOCK"; reason: string }
  | { decision: "RATE_LIMITED"; retryAfterSec: number; reason: string }
  | { decision: "PENDING"; actionId: number; expiresAt: number; workspaceId: number };

/** The approver's edited tool arguments ("Edit & Approve"). */
export interface ExecuteOverride {
  arguments: unknown;
}

/** Outbound guard verdict for a tool result. */
export interface ResultInspection {
  action: "pass" | "modified" | "block";
  /** The (possibly scrubbed) result to return when not blocked. */
  result: unknown;
  /** Explanation for the model when blocked. */
  message: string | null;
}

export type WaitResult<T> =
  | { status: "APPROVED"; value: T }
  | { status: "FAILED"; value?: T; error: string }
  | { status: "REJECTED" | "EXPIRED"; reason: string };

export interface ExecuteOutcome<T> {
  ok: boolean;
  /** Short text kept in the approval row (redacted before storage). */
  preview: string;
  value: T;
}

/** Registered while an MCP call waits; approvals.ts calls it when someone decides. */
export interface McpWaiter {
  /** Claims the call for an in-process decision before the DB row changes. False if already decided. */
  reserve(): boolean;
  /** Undo reserve() when the DB claim lost a race. */
  unreserve(): void;
  onDecision(decision: "APPROVE" | "REJECT", override?: ExecuteOverride): Promise<{ ok: boolean; preview: string }>;
}

export interface McpGuard {
  check(req: ToolCallRequest): Promise<GuardResult>;
  /**
   * Waits for a human decision on a PENDING tool call. `execute` runs only on APPROVE and
   * must perform the call, with `override.arguments` instead of the original arguments when the
   * approver edited them; its outcome is recorded on the approval row.
   */
  awaitDecision<T>(
    actionId: number,
    opts: { timeoutMs: number; signal?: AbortSignal },
    execute: (override?: ExecuteOverride) => Promise<ExecuteOutcome<T>>
  ): Promise<WaitResult<T>>;
  /**
   * Outbound response guard for a tool's result (bulk dumps, secrets). Synchronous so transports
   * can keep message order; the audit row is written in the background.
   */
  inspectResult(info: { toolName: string; workspaceId: number; callerIp: string; userAgent: string }, result: unknown): ResultInspection;
  /** "MCP /api/mcp/tools/<name>" */
  ruleKeyFor(toolName: string): string;
}

// Letters, digits, "_", "-", "." (no "..", no "/"), 1-128 chars: what MCP servers use in practice.
const TOOL_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;

export function createMcpGuard(ctx: GatewayContext): McpGuard {
  const audit = createAudit(ctx);
  const timed = <T>(p: Promise<T>, label: string): Promise<T> => withTimeout(p, ctx.dbTimeoutMs, label);

  async function check(req: ToolCallRequest): Promise<GuardResult> {
    const path = `${MCP_TOOL_PATH_PREFIX}${req.toolName}`;
    let caller: Caller | null = null;
    try {
      await ctx.ready;
      if (typeof req.toolName !== "string" || !TOOL_NAME.test(req.toolName) || req.toolName.includes("..")) {
        await audit.logRefusal({ method: MCP_RULE_METHOD, path: `${MCP_TOOL_PATH_PREFIX}(invalid)`, status: "BLOCKED", caller: null, userAgent: req.caller.userAgent, detail: "invalid MCP tool name" });
        return { decision: "BLOCK", reason: "Invalid tool name." };
      }
      const args = req.arguments === undefined ? {} : req.arguments;
      if (typeof args !== "object" || args === null || Array.isArray(args)) {
        await audit.logRefusal({ method: MCP_RULE_METHOD, path, status: "BLOCKED", caller: null, userAgent: req.caller.userAgent, detail: "params.arguments is not an object" });
        return { decision: "BLOCK", reason: "params.arguments must be an object." };
      }

      const config = ctx.config.load();
      caller = { ip: bucketIp(req.caller.ip), userAgent: req.caller.userAgent, agentKeyName: null, agentKeyId: null, agentKeyPrefix: null };

      // Workspace: the proxy's selector (header / mount / option) and/or the caller's mws_ key.
      const rawCredential = req.caller.agentKey ?? null;
      const workspaceKey = rawCredential && rawCredential.startsWith(WORKSPACE_KEY_PREFIX) ? rawCredential : null;
      const rawKey = workspaceKey ? null : rawCredential;
      const resolved = resolveWorkspace(ctx.workspaces, { pathSlug: null, headerSlug: req.workspace ?? null, key: workspaceKey });
      if (!resolved.ok) {
        await audit.logRefusal({ method: MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: `mcp ${resolved.reason}` });
        return { decision: "BLOCK", reason: resolved.message };
      }
      const workspace = resolved.workspace;
      const wsId = workspace.id;
      if (!ctx.workspaces.isEntitled(wsId, ctx.license.current().maxWorkspaces)) {
        await audit.logRefusal({ method: MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "mcp workspace over the license limit", workspaceId: wsId });
        return { decision: "BLOCK", reason: `Workspace "${workspace.slug}" is beyond this installation's Mont license.` };
      }
      const entry = ctx.workspaces.lookupEntry(wsId, MCP_RULE_METHOD, path);

      // Rate limit (per caller, per rule when the rule sets one).
      const custom = typeof entry?.rule.rateLimit === "number" && entry.rule.rateLimit > 0 ? entry.rule.rateLimit : null;
      const rate = custom
        ? ctx.limiters.checkRateLimit(req.caller.ip, custom, scopedRuleKey(wsId, entry!.key))
        : ctx.limiters.checkRateLimit(req.caller.ip, config.rateLimitPerMinute);
      if (rate.limited) {
        if (rate.firstLimited) {
          void audit.logRefusal({
            method: MCP_RULE_METHOD,
            path,
            status: "RATE_LIMITED",
            caller,
            userAgent: caller.userAgent,
            detail: "mcp tools/call",
            workspaceId: wsId,
            snapshot: buildSnapshot(ctx, { kind: "mcp", body: args, query: {}, headers: {}, callerId: callerIdOf(caller) }),
          });
        }
        return { decision: "RATE_LIMITED", retryAfterSec: rate.retryAfterSec, reason: `Rate limit of ${custom ?? config.rateLimitPerMinute} calls per minute exceeded.` };
      }

      // Agent key (a workspace's own mws_ key also authenticates the caller for that workspace).
      if (rawKey || (config.requireAgentApiKey && !resolved.authenticatedByKey)) {
        const info = rawKey ? await timed(ctx.agentKeys.verify(rawKey), "agent key lookup") : null;
        if (info && rawKey) {
          caller.agentKeyName = info.name;
          caller.agentKeyId = info.id;
          caller.agentKeyPrefix = rawKey.slice(0, AGENT_KEY_PREFIX.length + 4);
        } else if (config.requireAgentApiKey && !resolved.authenticatedByKey) {
          await audit.logRefusal({ method: MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: "missing or invalid agent key", workspaceId: wsId });
          return { decision: "BLOCK", reason: "A valid agent API key is required." };
        }
      }
      if (resolved.authenticatedByKey && caller.agentKeyName === null) caller.agentKeyName = `workspace:${workspace.slug}`;

      // Kill-switch.
      const blocked = ctx.blocklist.match({ ip: req.caller.ip, agentKeyId: caller.agentKeyId });
      if (blocked) {
        await audit.logRefusal({ method: MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: `caller blocked (${blocked.kind})`, workspaceId: wsId });
        return { decision: "BLOCK", reason: "This caller has been blocked by a gateway administrator." };
      }

      // Rules + payload policies on params.arguments (default deny).
      const rule: Rule = entry?.rule ?? { mode: "BLOCK", description: "" };
      const rawVerdict: PolicyDecision = entry ? evaluateRule(rule, { body: args, query: {}, headers: {} }) : { mode: "BLOCK", matched: "default-deny" };
      const { decision: ruleVerdict, shadow } = splitShadow(rawVerdict);
      const moded = applyOperatingMode(ctx, ruleVerdict, MCP_RULE_METHOD, "mcp", workspace);
      const callerId = callerIdOf(caller);
      const guard = await ctx.guards.evaluate(entry ? scopedRuleKey(wsId, entry.key) : null, entry?.rule ?? null, moded, args, callerId);
      const amount = extractAmount(args);
      const snapshot = (): string => buildSnapshot(ctx, { kind: "mcp", body: args, query: {}, headers: {}, callerId });
      try {
        const verdict = guard.decision;
        const why = guard.reason ? `${verdict.matched}: ${guard.reason}` : verdict.matched;

        if (verdict.mode === "BLOCK") {
          await audit.logRefusal({ method: MCP_RULE_METHOD, path, status: "BLOCKED", caller, userAgent: caller.userAgent, detail: `mcp ${why}`, amount, workspaceId: wsId, snapshot: snapshot() });
          let reason: string;
          if (verdict.matched === "default-deny") reason = `Tool "${req.toolName}" is not allowed by gateway rules.`;
          else if (verdict.matched === "lockdown") reason = "The gateway is in emergency lockdown: no tool calls are being accepted right now.";
          else if (verdict.matched === "duplicate") reason = `This "${req.toolName}" call duplicates one already made. ${guard.reason ?? ""}`.trim();
          else if (verdict.matched === "budget") reason = `The spending budget for "${req.toolName}" has been reached.`;
          else reason = `Tool "${req.toolName}" was blocked by a gateway policy.`;
          return { decision: "BLOCK", reason };
        }

        if (verdict.mode === "REQUIRE_APPROVAL") {
          const queued = await queuePending(ctx, audit, {
            kind: "mcp",
            method: MCP_RULE_METHOD,
            originalPath: path,
            cleanPath: path,
            originalBody: JSON.stringify(args),
            query: {},
            headers: { "user-agent": req.caller.userAgent },
            caller,
            agentReason: req.agentReason ?? null,
            matched: why,
            amount,
            workspace,
            snapshot: snapshot(),
          });
          if (!queued.ok) return { decision: "BLOCK", reason: queued.message };
          try {
            await guard.commit(queued.id);
          } catch (err) {
            await discardPending(ctx, queued.id, "Discarded: the duplicate-protection record could not be written.").catch(() => undefined);
            throw err;
          }
          return { decision: "PENDING", actionId: queued.id, expiresAt: queued.expiresAt, workspaceId: wsId };
        }

        await guard.commit(null);
        await audit.logStrict({
          method: MCP_RULE_METHOD,
          path,
          status: "ALLOWED",
          caller,
          userAgent: caller.userAgent,
          detail: shadow
            ? `mcp shadow: would have ${shadow === "BLOCK" ? "blocked" : "held for approval"} (${ruleVerdict.matched})`
            : verdict.matched === "rule"
              ? "mcp"
              : `mcp ${verdict.matched}`,
          amount,
          workspaceId: wsId,
          shadow,
          snapshot: snapshot(),
        });
        return { decision: "ALLOW", ruleKey: entry!.key, workspaceId: wsId };
      } finally {
        guard.release();
      }
    } catch (err) {
      console.error("[agent-gateway] FAIL-CLOSED (mcp tools/call):", err);
      return { decision: "BLOCK", reason: "The gateway could not safely evaluate this tool call, so it was refused." };
    }
  }

  function awaitDecision<T>(
    actionId: number,
    opts: { timeoutMs: number; signal?: AbortSignal },
    execute: (override?: ExecuteOverride) => Promise<ExecuteOutcome<T>>
  ): Promise<WaitResult<T>> {
    return new Promise((resolve) => {
      let settled = false;
      let decided = false;
      let poll: NodeJS.Timeout | undefined;
      let timer: NodeJS.Timeout | undefined;

      const finish = (r: WaitResult<T>): void => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (poll) clearInterval(poll);
        ctx.mcpWaiters.delete(actionId);
        opts.signal?.removeEventListener("abort", onAbort);
        resolve(r);
      };

      /** Runs the call (with the approver's edited arguments, if any) once a decision to APPROVE is final. */
      const run = async (override?: ExecuteOverride): Promise<{ ok: boolean; preview: string }> => {
        try {
          const out = await execute(override);
          finish(out.ok ? { status: "APPROVED", value: out.value } : { status: "FAILED", value: out.value, error: out.preview });
          return { ok: out.ok, preview: out.preview };
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          finish({ status: "FAILED", error: message });
          return { ok: false, preview: `Tool call failed: ${message}` };
        }
      };

      /** Approved by another process: it marked the row EXECUTING; we run the call and record it. */
      const runForRemoteApproval = async (): Promise<void> => {
        decided = true;
        // The approver may have edited the arguments: they travel encrypted on the row.
        let override: ExecuteOverride | undefined;
        try {
          const row = await ctx.db.get<{ patch_encrypted: string | null }>("SELECT patch_encrypted FROM pending_actions WHERE id = ?", [actionId]);
          if (row?.patch_encrypted) {
            const parsed = JSON.parse(decryptPayload(row.patch_encrypted, ctx.config.replayEncryptionKey())) as { arguments?: unknown };
            override = { arguments: parsed.arguments };
          }
        } catch (err) {
          // Fail closed: never run the unedited call when the approver asked for an edited one.
          console.error("Could not read the approver's edits for an MCP tool call:", err);
          const message = "The approver's edits could not be read, so the tool call was not executed.";
          finish({ status: "FAILED", error: message });
          await ctx.db
            .run("UPDATE pending_actions SET status = 'FAILED', response_preview = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ? AND status = 'EXECUTING'", [
              message,
              actionId,
            ])
            .catch(() => undefined);
          return;
        }
        const out = await run(override);
        const preview = ctx.redactor.text(out.preview).slice(0, 500);
        await ctx.db
          .run("UPDATE pending_actions SET status = ?, response_preview = ?, encrypted_payload = NULL, patch_encrypted = NULL WHERE id = ? AND status = 'EXECUTING'", [
            out.ok ? "APPROVED" : "FAILED",
            preview,
            actionId,
          ])
          .catch((err: unknown) => console.error("Could not record the MCP tool call outcome:", err));
      };

      const handleStatus = async (status: string | undefined): Promise<boolean> => {
        if (settled || decided) return true;
        if (status === "EXECUTING") {
          await runForRemoteApproval();
          return true;
        }
        if (status === "REJECTED") {
          decided = true;
          finish({ status: "REJECTED", reason: "Rejected by an approver." });
          return true;
        }
        if (status === "EXPIRED" || status === undefined) {
          decided = true;
          finish({ status: "EXPIRED", reason: "The approval request expired." });
          return true;
        }
        return false;
      };

      const expire = async (reason: string): Promise<void> => {
        if (settled || decided) return;
        ctx.mcpWaiters.delete(actionId);
        try {
          const r = await ctx.db.run(
            "UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'",
            [`Expired: ${reason}. The tool call was never executed.`, actionId]
          );
          if (r.changes === 0) {
            // Someone decided at the same moment: honour that decision instead.
            const row = await ctx.db.get<{ status: string }>("SELECT status FROM pending_actions WHERE id = ?", [actionId]);
            if (await handleStatus(row?.status)) return;
          }
        } catch (err) {
          console.error("Could not expire a held MCP tool call:", err);
        }
        decided = true;
        finish({ status: "EXPIRED", reason });
      };

      const onAbort = (): void => void expire("the agent disconnected while waiting for approval");
      if (opts.signal?.aborted) {
        void discardPending(ctx, actionId, "Expired: the agent disconnected before approval. The tool call was never executed.").catch(() => undefined);
        finish({ status: "EXPIRED", reason: "the agent disconnected" });
        return;
      }
      opts.signal?.addEventListener("abort", onAbort, { once: true });
      timer = setTimeout(() => void expire(`no decision within ${Math.round(opts.timeoutMs / 1000)} s`), opts.timeoutMs);
      timer.unref();

      // Decisions taken by another process (or by direct DB updates such as revoke) arrive via SQLite.
      let polling = false;
      poll = setInterval(() => {
        if (polling || settled || decided) return;
        polling = true;
        ctx.db
          .get<{ status: string }>("SELECT status FROM pending_actions WHERE id = ?", [actionId])
          .then((row) => handleStatus(row?.status))
          .catch(() => undefined)
          .finally(() => {
            polling = false;
          });
      }, 750);
      poll.unref();

      // Same-process decisions take the fast path and get the result back synchronously.
      let reserved = false;
      ctx.mcpWaiters.set(actionId, {
        reserve() {
          if (settled || decided) return false;
          reserved = true;
          decided = true; // the DB poll and the timeout now leave this call alone
          return true;
        },
        unreserve() {
          if (reserved && !settled) {
            reserved = false;
            decided = false;
          }
        },
        async onDecision(decision, override) {
          if (settled || (decided && !reserved)) return { ok: false, preview: "The agent was no longer waiting." };
          reserved = false;
          decided = true;
          if (decision === "REJECT") {
            finish({ status: "REJECTED", reason: "Rejected by an approver." });
            return { ok: true, preview: "rejected" };
          }
          return run(override);
        },
      });
    });
  }

  function inspectResult(info: { toolName: string; workspaceId: number; callerIp: string; userAgent: string }, result: unknown): ResultInspection {
    const settings = ctx.settings.peek().responseGuard;
    try {
      const v = inspectMcpResult(result, settings);
      if (v.action === "pass") return { action: "pass", result, message: null };
      const summary = describeFindings(v.findings);
      const blocked = v.action === "block";
      void audit.logRefusal({
        method: MCP_RULE_METHOD,
        path: `${MCP_TOOL_PATH_PREFIX}${info.toolName}`,
        status: blocked ? "RESPONSE_BLOCKED" : "RESPONSE_SCRUBBED",
        caller: { ip: bucketIp(info.callerIp), userAgent: info.userAgent, agentKeyName: null, agentKeyId: null, agentKeyPrefix: null },
        userAgent: info.userAgent,
        detail: `mcp result ${blocked ? "withheld" : "scrubbed"}: ${summary}`,
        workspaceId: info.workspaceId,
      });
      return blocked
        ? { action: "block", result, message: `Response Policy Violation: the tool result contained ${summary}, so the Mont gateway withheld it.` }
        : { action: "modified", result: v.result, message: null };
    } catch (err) {
      console.error("[agent-gateway] FAIL-CLOSED (mcp response guard):", err);
      return { action: "block", result, message: "Response Policy Violation: the tool result could not be inspected, so it was withheld." };
    }
  }

  return { check, awaitDecision, inspectResult, ruleKeyFor: (name) => `${MCP_RULE_METHOD} ${MCP_TOOL_PATH_PREFIX}${name}` };
}
