import type { GatewayContext } from "./context";
import type { LogStatus } from "./types";
import {
  MAX_LOG_PATH_LENGTH,
  MAX_LOG_UA_LENGTH,
  MAX_PENDING_ACTIONS,
  MAX_PENDING_BODY_BYTES,
  MAX_PENDING_DISPLAY_CHARS,
  PENDING_TTL_MS,
} from "./constants";
import { DEFAULT_WORKSPACE_ID, MAX_SNAPSHOT_CHARS } from "./constants";
import { encryptPayload } from "./crypto";
import { DbTimeoutError, redactQueryObject, redactQueryString, truncate, withTimeout } from "./utils";
import type { Workspace } from "./workspaces";
import { workspaceNotice } from "./notify";

/**
 * Audit logging and the approval queue, shared by the HTTP interceptor and the MCP tool guard.
 * Everything written here passes through ctx.redactor first: SQLite never holds a raw secret,
 * card number or (unless switched off) email / phone. The only unredacted copy of a queued
 * request is the AES-256-GCM encrypted replay payload, wiped as soon as the action is decided.
 */

/** Who sent the request, as far as the gateway can tell. */
export interface Caller {
  /** bucketIp() of the client address (IPv4 as is, IPv6 as its /64), or "stdio" for local MCP. */
  ip: string;
  userAgent: string;
  agentKeyName: string | null;
  agentKeyId: number | null;
  agentKeyPrefix: string | null;
}

export interface AuditEntry {
  method: string;
  path: string;
  status: LogStatus;
  caller: Caller | null;
  userAgent: string;
  actionId?: number | null;
  detail?: string | null;
  /** Money value of the request (body.amount etc.), for "money protected" totals. */
  amount?: number | null;
  /** Workspace (client) the request belongs to. Default workspace when omitted. */
  workspaceId?: number | null;
  /** What a SHADOW_* rule would have done ("BLOCK" / "APPROVAL"). */
  shadow?: string | null;
  /** Redacted request snapshot (see buildSnapshot) for the policy time-machine. */
  snapshot?: string | null;
}

export interface SnapshotInput {
  kind: "http" | "mcp";
  body: unknown;
  /** True when the body was not parsed (e.g. rate-limited before parsing). */
  bodyUnknown?: boolean;
  query: unknown;
  headers: Record<string, string | string[] | undefined>;
  callerId: string;
}

/**
 * The redacted copy of a request kept with its audit row, so "Test rules against history" can
 * replay it later. Same scrubbing as everything else stored; capped at MAX_SNAPSHOT_CHARS (a
 * larger request keeps its query and headers but is marked truncated).
 */
export function buildSnapshot(ctx: GatewayContext, s: SnapshotInput): string {
  const headers = ctx.redactor.headers(s.headers);
  const smallHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers).slice(0, 40)) smallHeaders[k] = v.slice(0, 512);
  const base = { v: 1, kind: s.kind, query: ctx.redactor.json(redactQueryObject(s.query)), headers: smallHeaders, caller: s.callerId };
  if (s.bodyUnknown) return JSON.stringify({ ...base, bodyUnknown: true });
  const full = JSON.stringify({ ...base, body: s.body === undefined ? null : ctx.redactor.json(s.body) });
  if (full.length <= MAX_SNAPSHOT_CHARS) return full;
  const lean = JSON.stringify({ ...base, truncated: true });
  return lean.length <= MAX_SNAPSHOT_CHARS ? lean : JSON.stringify({ v: 1, kind: s.kind, caller: s.callerId, truncated: true });
}

export interface Audit {
  /** Throws on failure (including timeouts). Use before anything is forwarded or queued. */
  logStrict(e: AuditEntry): Promise<void>;
  /** Best-effort, for refusals: the request is refused whether or not the row lands. */
  logRefusal(e: AuditEntry): Promise<void>;
}

export function createAudit(ctx: GatewayContext): Audit {
  async function logStrict(e: AuditEntry): Promise<void> {
    const write = ctx.db.run(
      `INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount, workspace_id, shadow, request_snapshot)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        new Date().toISOString(),
        e.method,
        truncate(ctx.redactor.text(e.path), MAX_LOG_PATH_LENGTH),
        e.status,
        truncate(ctx.redactor.text(e.userAgent), MAX_LOG_UA_LENGTH),
        e.caller?.agentKeyName ?? null,
        e.actionId ?? null,
        e.caller?.ip ?? null,
        e.detail ? ctx.redactor.text(e.detail) : null,
        e.amount ?? null,
        e.workspaceId ?? DEFAULT_WORKSPACE_ID,
        e.shadow ?? null,
        e.snapshot ?? null,
      ]
    );
    try {
      await withTimeout(write, ctx.dbTimeoutMs, "audit log write");
      ctx.ledger.kick();
    } catch (err) {
      // The request is about to be refused. If the timed-out row still lands later, it must
      // not claim the request was ALLOWED/QUEUED.
      if (err instanceof DbTimeoutError && (e.status === "ALLOWED" || e.status === "QUEUED")) {
        write.then(
          (r) => void correctLateRow(r.lastID, e),
          () => undefined
        );
      }
      throw err;
    }
  }

  /**
   * A timed-out ALLOWED/QUEUED row that landed late is corrected in place while it is still
   * unsealed; once the ledger has sealed it (rows are append-only from then on), a correcting
   * BLOCKED row is appended instead.
   */
  async function correctLateRow(id: number, e: AuditEntry): Promise<void> {
    const note = "Refused (fail-closed): the audit write timed out, so the request was not forwarded.";
    try {
      const r = await ctx.db.run("UPDATE agent_logs SET status = 'BLOCKED', detail = ? WHERE id = ? AND row_hash IS NULL", [note, id]);
      if (r.changes === 0) {
        await ctx.db.run(
          `INSERT INTO agent_logs (timestamp, method, path, status, user_agent, agent_key, action_id, caller_ip, detail, amount, workspace_id)
           VALUES (?, ?, ?, 'BLOCKED', ?, ?, ?, ?, ?, NULL, ?)`,
          [
            new Date().toISOString(),
            e.method,
            truncate(ctx.redactor.text(e.path), MAX_LOG_PATH_LENGTH),
            truncate(ctx.redactor.text(e.userAgent), MAX_LOG_UA_LENGTH),
            e.caller?.agentKeyName ?? null,
            e.actionId ?? null,
            e.caller?.ip ?? null,
            `Correction for log #${id}: ${note}`,
            e.workspaceId ?? DEFAULT_WORKSPACE_ID,
          ]
        );
      }
      ctx.ledger.kick();
    } catch {
      // best effort
    }
  }

  async function logRefusal(e: AuditEntry): Promise<void> {
    try {
      await logStrict(e);
    } catch (err) {
      console.error("Failed to write log for a refused request:", err);
    }
  }

  return { logStrict, logRefusal };
}

export interface QueueRequest {
  kind: "http" | "mcp";
  method: string;
  /** Original path including the query string. Encrypted for replay; shown redacted. */
  originalPath: string;
  /** Path without query (audit log). */
  cleanPath: string;
  /** Original body text (JSON), encrypted for replay. */
  originalBody: string | null;
  query: unknown;
  headers: Record<string, string | string[] | undefined>;
  caller: Caller;
  agentReason: string | null;
  /** PolicyDecision.matched */
  matched: string;
  amount?: number | null;
  workspace: Workspace;
  /** Redacted snapshot for the QUEUED audit row (policy time-machine). */
  snapshot?: string | null;
}

export type QueueResult =
  | { ok: true; id: number; queuedAt: string; expiresAt: number }
  | { ok: false; status: number; error: string; message: string; retryAfter?: number };

export async function queuePending(ctx: GatewayContext, audit: Audit, q: QueueRequest): Promise<QueueResult> {
  const timed = <T>(p: Promise<T>, label: string): Promise<T> => withTimeout(p, ctx.dbTimeoutMs, label);
  const r = ctx.redactor;

  const wsId = q.workspace.id;
  const pending = await timed(
    ctx.db.get<{ count: number }>("SELECT COUNT(*) as count FROM pending_actions WHERE status = 'PENDING'"),
    "approval queue count"
  );
  if ((pending?.count ?? 0) >= MAX_PENDING_ACTIONS) {
    await audit.logRefusal({ method: q.method, path: q.cleanPath, status: "BLOCKED", caller: q.caller, userAgent: q.caller.userAgent, detail: "approval queue full", workspaceId: wsId });
    return { ok: false, status: 503, error: "Service Unavailable", message: "The approval queue is full. Try again later.", retryAfter: 60 };
  }

  // Queued requests are stored until decided, so cap their size.
  if (q.originalBody !== null && Buffer.byteLength(q.originalBody) > MAX_PENDING_BODY_BYTES) {
    await audit.logRefusal({ method: q.method, path: q.cleanPath, status: "BLOCKED", caller: q.caller, userAgent: q.caller.userAgent, detail: "approval body too large", workspaceId: wsId });
    return {
      ok: false,
      status: 413,
      error: "Payload Too Large",
      message: `Requests that need approval can have a body of at most ${MAX_PENDING_BODY_BYTES / 1024} KB.`,
    };
  }

  const encryptedPayload = encryptPayload(JSON.stringify({ path: q.originalPath, body: q.originalBody }), ctx.config.replayEncryptionKey());
  const redactedBody = r.jsonText(q.originalBody);
  const displayBody =
    redactedBody !== null && redactedBody.length > MAX_PENDING_DISPLAY_CHARS
      ? `${redactedBody.slice(0, MAX_PENDING_DISPLAY_CHARS)}… [truncated]`
      : redactedBody;
  const query = r.json(redactQueryObject(q.query)) as Record<string, unknown>;
  const agentReason = q.agentReason ? r.text(q.agentReason) : null;
  const queuedAt = new Date().toISOString();
  const expiresAt = Date.now() + PENDING_TTL_MS;
  const displayPath = truncate(r.text(redactQueryString(q.originalPath)), MAX_LOG_PATH_LENGTH);
  const userAgent = truncate(r.text(q.caller.userAgent), MAX_LOG_UA_LENGTH);

  const insert = ctx.db.run(
    `INSERT INTO pending_actions
       (timestamp, method, path, headers, body, status, expires_at, agent_key, encrypted_payload,
        query_json, caller_ip, caller_ua, agent_key_id, agent_key_prefix, agent_reason, matched_policy, kind, owner, workspace_id)
     VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      queuedAt,
      q.method,
      displayPath,
      JSON.stringify(r.headers(q.headers)),
      displayBody,
      expiresAt,
      q.caller.agentKeyName,
      encryptedPayload,
      JSON.stringify(query),
      q.caller.ip,
      userAgent,
      q.caller.agentKeyId,
      q.caller.agentKeyPrefix,
      agentReason,
      q.matched,
      q.kind,
      q.kind === "mcp" ? ctx.instanceId : null,
      wsId,
    ]
  );

  // If the insert outlives the timeout, or anything after it fails, the agent is told the
  // request failed, so the queued row must never be approvable: expire it when it lands.
  const discard = (id: number): void => {
    void ctx.db
      .run(
        "UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'",
        ["Discarded: the gateway failed while queueing this request and told the agent it was refused.", id]
      )
      .catch((err: unknown) => console.error("Could not discard a half-queued action:", err));
  };

  let inserted: { lastID: number };
  try {
    inserted = await timed(insert, "approval queue insert");
  } catch (err) {
    if (err instanceof DbTimeoutError) insert.then((res) => discard(res.lastID), () => undefined);
    throw err;
  }

  try {
    await audit.logStrict({
      method: q.method,
      path: q.cleanPath,
      status: "QUEUED",
      caller: q.caller,
      userAgent: q.caller.userAgent,
      actionId: inserted.lastID,
      detail: q.kind === "mcp" ? `mcp ${q.matched}` : q.matched,
      amount: q.amount ?? null,
      workspaceId: wsId,
      snapshot: q.snapshot ?? null,
    });
  } catch (err) {
    discard(inserted.lastID);
    throw err;
  }

  // Phone / chat notifications. Fire-and-forget: they can never change the outcome.
  void ctx.notifier.notifyPending({
    id: inserted.lastID,
    queuedAt,
    expiresAt,
    method: q.method,
    path: displayPath,
    body: displayBody,
    query,
    callerIp: q.caller.ip,
    callerUa: userAgent,
    agentKey: q.caller.agentKeyName,
    agentKeyPrefix: q.caller.agentKeyPrefix,
    agentReason,
    matchedPolicy: q.matched,
    workspace: workspaceNotice(q.workspace),
  });

  return { ok: true, id: inserted.lastID, queuedAt, expiresAt };
}

/** Marks an action that is no longer queued-for-real (agent gone, error after insert) as EXPIRED. */
export function discardPending(ctx: GatewayContext, id: number, reason: string): Promise<void> {
  return ctx.db
    .run(
      "UPDATE pending_actions SET status = 'EXPIRED', encrypted_payload = NULL, response_preview = ? WHERE id = ? AND status = 'PENDING'",
      [reason, id]
    )
    .then(() => undefined);
}
