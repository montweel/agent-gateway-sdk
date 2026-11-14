"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JUSTIFICATION_FIELDS = void 0;
exports.cleanAgentReason = cleanAgentReason;
exports.justificationFromPayload = justificationFromPayload;
exports.justificationFromBodyText = justificationFromBodyText;
exports.justificationFromHeaders = justificationFromHeaders;
exports.justificationFromMcpMeta = justificationFromMcpMeta;
const constants_1 = require("./constants");
const utils_1 = require("./utils");
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
exports.JUSTIFICATION_FIELDS = ["justification", "_justification", "mont_justification", "reason", "summary"];
/** Cleans free-text an agent sent as its justification. */
function cleanAgentReason(raw) {
    if (typeof raw !== "string" || !raw)
        return null;
    // eslint-disable-next-line no-control-regex
    const clean = raw.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s{2,}/g, " ").trim();
    return clean ? (0, utils_1.truncate)(clean, constants_1.MAX_AGENT_REASON_LENGTH) : null;
}
/** First non-empty justification-like string field at the top level of a payload. */
function justificationFromPayload(body) {
    if (typeof body !== "object" || body === null || Array.isArray(body))
        return null;
    const b = body;
    for (const key of exports.JUSTIFICATION_FIELDS) {
        const found = cleanAgentReason(b[key]);
        if (found)
            return found;
    }
    return null;
}
/** Parses a JSON body text and looks for a justification field. Never throws. */
function justificationFromBodyText(text) {
    if (!text)
        return null;
    try {
        return justificationFromPayload(JSON.parse(text));
    }
    catch {
        return null;
    }
}
/** Header-provided justification (x-mont-justification beats x-agent-reason). */
function justificationFromHeaders(get) {
    return cleanAgentReason(get(constants_1.JUSTIFICATION_HEADER)) ?? cleanAgentReason(get(constants_1.AGENT_REASON_HEADER));
}
/** MCP tools/call params._meta justification. */
function justificationFromMcpMeta(meta) {
    return cleanAgentReason(meta["mont/justification"]) ?? cleanAgentReason(meta["mont/reason"]);
}
