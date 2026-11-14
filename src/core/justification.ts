import { AGENT_REASON_HEADER, JUSTIFICATION_HEADER, MAX_AGENT_REASON_LENGTH } from "./constants";
import { truncate } from "./utils";

/**
 * "Why does the agent want to do this?" - shown to the approver right above Approve / Reject.
 *
 * Sources, first match wins:
 *   1. x-mont-justification header (HTTP request, or the MCP client's HTTP request)
 *   2. x-agent-reason header (older name, still honoured)
 *   3. MCP params._meta["mont/justification"] / ["mont/reason"]
 *   4. a top-level string field in the payload: justification, reason, summary
 *      (also _justification / mont_justification, for agents that namespace it)
 *
 * The text is cleaned of control characters and capped; it is redacted before storage like
 * everything else (pendingQueue.ts).
 */

/** Payload fields searched for a justification, in priority order. */
export const JUSTIFICATION_FIELDS = ["justification", "_justification", "mont_justification", "reason", "summary"] as const;

/** Cleans free-text an agent sent as its justification. */
export function cleanAgentReason(raw: unknown): string | null {
  if (typeof raw !== "string" || !raw) return null;
  // eslint-disable-next-line no-control-regex
  const clean = raw.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s{2,}/g, " ").trim();
  return clean ? truncate(clean, MAX_AGENT_REASON_LENGTH) : null;
}

/** First non-empty justification-like string field at the top level of a payload. */
export function justificationFromPayload(body: unknown): string | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  for (const key of JUSTIFICATION_FIELDS) {
    const found = cleanAgentReason(b[key]);
    if (found) return found;
  }
  return null;
}

/** Parses a JSON body text and looks for a justification field. Never throws. */
export function justificationFromBodyText(text: string | null): string | null {
  if (!text) return null;
  try {
    return justificationFromPayload(JSON.parse(text) as unknown);
  } catch {
    return null;
  }
}

/** Header-provided justification (x-mont-justification beats x-agent-reason). */
export function justificationFromHeaders(get: (name: string) => string | undefined): string | null {
  return cleanAgentReason(get(JUSTIFICATION_HEADER)) ?? cleanAgentReason(get(AGENT_REASON_HEADER));
}

/** MCP tools/call params._meta justification. */
export function justificationFromMcpMeta(meta: Record<string, unknown>): string | null {
  return cleanAgentReason(meta["mont/justification"]) ?? cleanAgentReason(meta["mont/reason"]);
}
