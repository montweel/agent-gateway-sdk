"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildEvidenceBundle = buildEvidenceBundle;
exports.bundleToJson = bundleToJson;
exports.mdEscape = mdEscape;
exports.bundleToMarkdown = bundleToMarkdown;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const auditLedger_1 = require("./auditLedger");
const operatingMode_1 = require("./operatingMode");
const protection_1 = require("./protection");
const complianceTemplates_1 = require("./complianceTemplates");
const redactor_1 = require("./redactor");
/**
 * Auditor Evidence Pack: everything an auditor needs about a slice of the audit ledger, in one file.
 *
 *   metadata            who generated it, when, with which filters, template and frameworks
 *   ledgerVerification  a live re-hash of the WHOLE chain (a chain cannot be verified from a subset)
 *   policySnapshot      rules, redaction / privacy / response-guard policy; secrets and URLs omitted
 *   summary             request counts, per-agent and verified vs agent-claimed end-user breakdowns
 *   logs                the scoped rows (already redacted when stored) with their chain hashes
 *
 * JSON bundles carry bundleSha256 = SHA-256 (hex) of JSON.stringify({ metadata, ledgerVerification,
 * policySnapshot, summary, logs }) - compact, keys in file order. It proves the file was not changed
 * after download; it is a checksum, not a signature (whoever edits the file can recompute it). Proof
 * against the gateway itself is the ledger head hash, which the daily digest also sends off-box.
 */
/** Rows read for one pack (the ledger keeps MAX_LOG_ROWS = 10,000 by default, so normally all of them). */
const MAX_PACK_ROWS = 50000;
/** Rows printed in the Markdown report's table (the JSON bundle always has every row). */
const MAX_REPORT_TABLE_ROWS = 1000;
const SNIPPET_CHARS = 120;
let cachedVersion;
function packageVersion() {
    if (cachedVersion)
        return cachedVersion;
    try {
        // src/core and dist/core are both two levels below the package root.
        const pkg = JSON.parse(fs_1.default.readFileSync(path_1.default.join(__dirname, "..", "..", "package.json"), "utf8"));
        cachedVersion = pkg.version ?? "unknown";
    }
    catch {
        cachedVersion = "unknown";
    }
    return cachedVersion;
}
function parseMaybe(text) {
    if (text === null)
        return null;
    try {
        return JSON.parse(text);
    }
    catch {
        return text;
    }
}
const isDecisionRow = (r) => (r.user_agent ?? "").startsWith("decided_by:");
function emptyCounts() {
    return { total: 0, allowed: 0, blocked: 0, heldForApproval: 0, approved: 0, rejected: 0 };
}
function tally(c, r) {
    // Human decision rows record what happened to a request already counted when it was queued.
    if (!isDecisionRow(r))
        c.total++;
    switch (r.status) {
        case "ALLOWED":
            c.allowed++;
            break;
        case "BLOCKED":
        case "RATE_LIMITED":
        case "RESPONSE_BLOCKED":
            // A revocation is a BLOCKED decision row: it blocks the caller, not a new request.
            if (!isDecisionRow(r))
                c.blocked++;
            break;
        case "QUEUED":
            c.heldForApproval++;
            break;
        case "APPROVED":
            c.approved++;
            break;
        case "REJECTED":
            c.rejected++;
            break;
    }
}
function summarize(rows) {
    const totals = emptyCounts();
    const byStatus = {};
    const agents = new Map();
    const users = new Map();
    const approvers = new Map();
    let verifiedRows = 0;
    let agentClaimedRows = 0;
    let noEndUserRows = 0;
    for (const r of rows) {
        tally(totals, r);
        byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
        const agent = r.agent_key ?? "(no agent key)";
        const a = agents.get(agent) ?? emptyCounts();
        tally(a, r);
        agents.set(agent, a);
        if (r.end_user) {
            const u = users.get(r.end_user) ?? { verifiedRows: 0, agentClaimedRows: 0 };
            if (r.end_user_verified === 1) {
                verifiedRows++;
                u.verifiedRows++;
            }
            else {
                agentClaimedRows++;
                u.agentClaimedRows++;
            }
            users.set(r.end_user, u);
        }
        else
            noEndUserRows++;
        if (r.approved_by && r.status === "APPROVED")
            approvers.set(r.approved_by, (approvers.get(r.approved_by) ?? 0) + 1);
    }
    const userList = [...users.entries()].map(([endUser, u]) => ({ endUser, ...u }));
    return {
        ...totals,
        auditRows: rows.length,
        byStatus,
        perAgent: [...agents.entries()].map(([agent, c]) => ({ agent, ...c })).sort((x, y) => y.total - x.total || x.agent.localeCompare(y.agent)),
        endUsers: {
            verifiedRows,
            agentClaimedRows,
            noEndUserRows,
            distinctVerified: userList.filter((u) => u.verifiedRows > 0).length,
            distinctAgentClaimed: userList.filter((u) => u.agentClaimedRows > 0).length,
            top: userList.sort((x, y) => y.verifiedRows + y.agentClaimedRows - (x.verifiedRows + x.agentClaimedRows)).slice(0, 50),
        },
        approvers: [...approvers.entries()].map(([approvedBy, approvals]) => ({ approvedBy, approvals })).sort((x, y) => y.approvals - x.approvals),
    };
}
function toLog(ctx, r) {
    const snapshot = parseMaybe(r.request_snapshot);
    const request = snapshot && typeof snapshot === "object"
        ? { body: snapshot.body ?? null, query: snapshot.query ?? null }
        : null;
    return {
        id: r.id,
        timestamp: r.timestamp,
        workspace: ctx.workspaces.get(r.workspace_id ?? 1)?.slug ?? null,
        agent: r.agent_key,
        callerIp: r.caller_ip,
        endUser: r.end_user,
        endUserVerification: r.end_user ? (r.end_user_verified === 1 ? "verified" : "agent-claimed") : null,
        method: r.method,
        route: r.path,
        status: r.status,
        actionId: r.action_id,
        // approved_by holds whoever decided: an approver on APPROVED rows, a rejecter on REJECTED rows.
        approvedBy: r.status === "APPROVED" ? r.approved_by : null,
        rejectedBy: r.status === "REJECTED" ? r.approved_by : null,
        decidedBy: isDecisionRow(r) ? (r.user_agent ?? "").slice("decided_by:".length) : null,
        detail: r.detail,
        amount: r.amount,
        shadow: r.shadow,
        request,
        response: parseMaybe(r.response_payload),
        approverEdit: r.original_payload || r.modified_payload ? { original: parseMaybe(r.original_payload), modified: parseMaybe(r.modified_payload) } : null,
        sealed: r.row_hash !== null,
        prevHash: r.prev_hash,
        rowHash: r.row_hash,
    };
}
/**
 * Secret patterns (tokens, Slack / Telegram credentials, card numbers) masked in every string, at
 * any depth. Keys are left alone: a rule key like "POST /api/*token*" is not a secret field.
 */
function scrubStrings(value) {
    if (typeof value === "string")
        return (0, redactor_1.scrubSecrets)(value).text;
    if (Array.isArray(value))
        return value.map(scrubStrings);
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrubStrings(v)]));
    }
    return value;
}
/**
 * Governance snapshot. Built from an explicit allow-list: notification channels (Telegram / Slack
 * tokens, webhook URLs and secrets), the rollback webhook, upstream URLs and every key are never
 * read into it. As a second line of defence, free text (rule descriptions) is secret-scrubbed.
 */
function policySnapshot(ctx, scoped) {
    return scrubStrings(buildPolicySnapshot(ctx, scoped));
}
function buildPolicySnapshot(ctx, scoped) {
    const config = ctx.config.load();
    const settings = ctx.settings.peek();
    const workspaces = scoped ? [scoped] : ctx.workspaces.list();
    return {
        workspaces: workspaces.map((ws) => ({
            slug: ws.slug,
            name: ws.name,
            operatingMode: (0, operatingMode_1.effectiveMode)(ctx, ws),
            upstreamConfigured: Boolean(ws.upstreamUrl ?? config.targetUrl),
            requireWorkspaceKey: ws.requireKey,
            rules: ctx.workspaces.rules(ws.id),
        })),
        audit: config.audit,
        privacy: settings.privacy,
        responseGuard: settings.responseGuard,
        access: {
            requireAgentApiKey: config.requireAgentApiKey,
            rateLimitPerMinute: config.rateLimitPerMinute,
            ssoTrustProxyHeader: config.ssoTrustProxyHeader,
        },
        omitted: [
            "SSO shared secret",
            "replay encryption key",
            "approval signing secret",
            "Telegram and Slack bot / app tokens",
            "Slack incoming-webhook URL",
            "custom and rollback webhook URLs and signing secrets",
            "upstream URLs (may embed credentials)",
            "agent and workspace API keys",
        ],
    };
}
function ledgerSection(report) {
    return {
        status: report.ok ? "PASS" : "FAIL",
        ok: report.ok,
        scope: "entire ledger (every retained row), independent of the export filters",
        sealedRowsVerified: report.checked,
        unsealedRows: report.unsealed,
        firstRowId: report.firstId,
        lastRowId: report.lastId,
        chainAnchor: report.checkpoint
            ? { kind: "retention checkpoint", afterRowId: report.checkpoint.id, hash: report.checkpoint.hash }
            : { kind: "genesis", hash: auditLedger_1.GENESIS_HASH },
        latestRowHash: report.headHash,
        recordedHead: report.storedHead,
        brokenAtRowId: report.brokenAt,
        reason: report.reason,
        verifiedAt: report.verifiedAt,
        algorithm: "SHA-256 hash chain: row_hash = SHA-256(prev_hash + \"\\n\" + canonical JSON of the row)",
    };
}
async function buildEvidenceBundle(ctx, scoped, filters, generatedBy) {
    // Seal what was written a moment ago, then verify the whole chain.
    await ctx.ledger.sealPending();
    const verification = await ctx.ledger.verify();
    const wf = (0, protection_1.workspaceFilter)(scoped?.id ?? null);
    let sql = `SELECT id, timestamp, workspace_id, method, path, status, agent_key, caller_ip, user_agent, action_id, detail, amount, shadow,
                    end_user, end_user_verified, approved_by, request_snapshot, response_payload, original_payload, modified_payload, prev_hash, row_hash
             FROM agent_logs WHERE 1=1${wf.sql}`;
    const params = [...wf.params];
    if (filters.from) {
        sql += " AND timestamp >= ?";
        params.push(filters.from);
    }
    if (filters.to) {
        sql += " AND timestamp <= ?";
        params.push(filters.to);
    }
    if (filters.agentName) {
        sql += " AND agent_key = ?";
        params.push(filters.agentName);
    }
    if (filters.endUser) {
        sql += " AND end_user = ?";
        params.push(filters.endUser);
    }
    sql += " ORDER BY id ASC LIMIT ?";
    params.push(MAX_PACK_ROWS + 1);
    const rows = await ctx.db.all(sql, params);
    const truncated = rows.length > MAX_PACK_ROWS;
    if (truncated)
        rows.length = MAX_PACK_ROWS;
    const audit = ctx.config.load().audit;
    const template = audit.activeTemplate ? (0, complianceTemplates_1.findComplianceTemplate)(audit.activeTemplate) : undefined;
    return {
        metadata: {
            title: "AI Agent Compliance & Audit Attestation",
            generator: `Mont agent-gateway-sdk ${packageVersion()}`,
            generatedAt: new Date().toISOString(),
            generatedBy,
            scope: {
                workspace: scoped?.slug ?? "all",
                from: filters.from,
                to: filters.to,
                agentName: filters.agentName,
                endUser: filters.endUser,
            },
            industryTemplate: template ? { id: template.id, name: template.name } : null,
            complianceFrameworks: audit.complianceFrameworks ?? template?.frameworks ?? [],
            rowCount: rows.length,
            truncated,
            redaction: "Payloads were redacted before they were stored; this pack adds nothing unredacted.",
            checksumMethod: "bundleSha256 = SHA-256 (hex) of JSON.stringify({ metadata, ledgerVerification, policySnapshot, summary, logs }) with no whitespace, keys in file order.",
        },
        ledgerVerification: ledgerSection(verification),
        policySnapshot: policySnapshot(ctx, scoped),
        summary: summarize(rows),
        logs: rows.map((r) => toLog(ctx, r)),
    };
}
/** The JSON evidence file: the bundle plus its SHA-256 checksum (see the header). */
function bundleToJson(bundle) {
    const body = JSON.stringify({
        metadata: bundle.metadata,
        ledgerVerification: bundle.ledgerVerification,
        policySnapshot: bundle.policySnapshot,
        summary: bundle.summary,
        logs: bundle.logs,
    });
    const bundleSha256 = crypto_1.default.createHash("sha256").update(body, "utf8").digest("hex");
    return JSON.stringify({ ...JSON.parse(body), bundleSha256 }, null, 2);
}
// ---------------------------------------------------------------------------
// Markdown attestation report
// ---------------------------------------------------------------------------
/** Agent-controlled text must not become links, HTML or table breaks in the auditor's viewer. */
function mdEscape(value) {
    if (value === null || value === undefined || value === "")
        return "—";
    return String(value)
        .replace(/[\r\n]+/g, " ")
        .replace(/[\\`*_[\]<>|#!~]/g, (c) => `\\${c}`);
}
function snippet(value) {
    if (value === null || value === undefined)
        return "—";
    const text = typeof value === "string" ? value : JSON.stringify(value);
    return mdEscape(text.length > SNIPPET_CHARS ? `${text.slice(0, SNIPPET_CHARS)}…` : text);
}
function responseSnippet(response) {
    if (response && typeof response === "object" && "status" in response) {
        const r = response;
        return `${r.status} ${snippet(r.note ? `(${r.note})` : (r.body ?? ""))}`;
    }
    return snippet(response);
}
const table = (head, rows) => [`| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`, ...rows.map((r) => `| ${r.join(" | ")} |`)].join("\n");
function bundleToMarkdown(bundle) {
    const m = bundle.metadata;
    const l = bundle.ledgerVerification;
    const p = bundle.policySnapshot;
    const s = bundle.summary;
    const out = [];
    out.push("# AI Agent Compliance & Audit Attestation Report", "");
    out.push(`Generated ${mdEscape(m.generatedAt)} by ${mdEscape(m.generatedBy)} with ${mdEscape(m.generator)}.`, "");
    out.push("## 1. Audit scope", "");
    out.push(table(["Item", "Value"], [
        ["Workspace", mdEscape(m.scope.workspace)],
        ["From", mdEscape(m.scope.from ?? "start of the retained ledger")],
        ["To", mdEscape(m.scope.to ?? m.generatedAt)],
        ["Agent filter", mdEscape(m.scope.agentName ?? "all agents")],
        ["End-user filter", mdEscape(m.scope.endUser ?? "all end users")],
        ["Industry template", mdEscape(m.industryTemplate?.name ?? "none")],
        ["Compliance frameworks", mdEscape(m.complianceFrameworks.length ? m.complianceFrameworks.join(", ") : "none declared")],
        ["Audit rows in scope", `${m.rowCount}${m.truncated ? " (truncated: narrow the date range)" : ""}`],
    ]), "");
    out.push("## 2. Cryptographic ledger integrity certificate", "");
    out.push(l.status === "PASS"
        ? "**Result: PASS.** Every retained audit row was re-hashed and links to the row before it. No row was edited, deleted, inserted or reordered."
        : `**Result: FAIL.** Tampering detected${l.brokenAtRowId ? ` at row #${l.brokenAtRowId}` : ""}: ${mdEscape(l.reason)}`, "");
    out.push(table(["Item", "Value"], [
        ["Verification scope", "Entire ledger, independent of the filters above"],
        ["Sealed rows verified", String(l.sealedRowsVerified)],
        ["Rows still sealing", String(l.unsealedRows)],
        ["Row range", `#${l.firstRowId ?? "—"} to #${l.lastRowId ?? "—"}`],
        [l.chainAnchor.kind === "genesis" ? "Genesis hash" : `Retention checkpoint (after row #${l.chainAnchor.afterRowId})`, `\`${l.chainAnchor.hash}\``],
        ["Latest row hash", `\`${l.latestRowHash}\``],
        ["Verified at", mdEscape(l.verifiedAt)],
        ["Algorithm", "SHA-256 hash chain over each row's canonical JSON"],
    ]), "", "Compare the latest row hash with the one in the gateway's daily digest (sent off-box) to confirm the chain was not rewritten as a whole.", "");
    out.push("## 3. Governance & redaction policy snapshot", "");
    out.push(table(["Control", "Setting"], [
        ["Response payload capture", p.audit.capturePayloads ? "on" : "off"],
        ["Custom redacted keys", mdEscape(p.audit.redactKeys.join(", ") || "none")],
        ["Always redacted", "passwords, tokens, API keys, Authorization / Bearer values, cookies, JWTs, card numbers, CVV, SSN"],
        ["Email / phone masking", `${p.privacy.redactEmails ? "emails masked" : "emails kept"}, ${p.privacy.redactPhones ? "phones masked" : "phones kept"}`],
        ["Outbound response guard", p.responseGuard.enabled ? "on" : "off"],
        ["Agent API key required", p.access.requireAgentApiKey ? "yes" : "no"],
        ["Global rate limit", `${p.access.rateLimitPerMinute} requests / minute / IP`],
        ["Trusted identity proxy (SSO)", p.access.ssoTrustProxyHeader ? "on (verified end users possible)" : "off (end users are agent-claimed)"],
    ]), "");
    for (const ws of p.workspaces) {
        const entries = Object.entries(ws.rules);
        out.push(`### Firewall rules: workspace \`${mdEscape(ws.slug)}\` (mode: ${mdEscape(ws.operatingMode)})`, "");
        out.push(entries.length
            ? table(["Rule", "Mode", "Description"], entries.map(([k, r]) => [mdEscape(k), mdEscape(r.mode), mdEscape(r.description)]))
            : "No rules: every request is denied by default.", "");
    }
    out.push(`Omitted from this report: ${p.omitted.join("; ")}.`, "");
    out.push("## 4. Summary metrics", "");
    out.push(table(["Metric", "Count"], [
        ["Total requests", String(s.total)],
        ["Allowed", String(s.allowed)],
        ["Blocked (rules, rate limits, response guard)", String(s.blocked)],
        ["Held for approval", String(s.heldForApproval)],
        ["Approved by a human", String(s.approved)],
        ["Rejected by a human", String(s.rejected)],
        ["Audit rows (including decision rows)", String(s.auditRows)],
    ]), "");
    out.push("### Per agent", "");
    out.push(s.perAgent.length
        ? table(["Agent", "Requests", "Allowed", "Blocked", "Held", "Approved", "Rejected"], s.perAgent.map((a) => [mdEscape(a.agent), String(a.total), String(a.allowed), String(a.blocked), String(a.heldForApproval), String(a.approved), String(a.rejected)]))
        : "No activity in scope.", "");
    out.push("### End-user attribution", "");
    out.push(table(["Attribution", "Rows", "Distinct users"], [
        ["Verified (identity proxy, SSO shared secret)", String(s.endUsers.verifiedRows), String(s.endUsers.distinctVerified)],
        ["Agent-claimed (unverified)", String(s.endUsers.agentClaimedRows), String(s.endUsers.distinctAgentClaimed)],
        ["No end user named", String(s.endUsers.noEndUserRows), "—"],
    ]), "");
    if (s.approvers.length) {
        out.push("### Approvers", "");
        out.push(table(["Approved by", "Approvals"], s.approvers.map((a) => [mdEscape(a.approvedBy), String(a.approvals)])), "");
    }
    out.push("## 5. Scoped transaction log", "");
    const shown = bundle.logs.slice(-MAX_REPORT_TABLE_ROWS);
    if (bundle.logs.length > shown.length) {
        out.push(`Showing the newest ${shown.length} of ${bundle.logs.length} rows. The JSON evidence bundle contains every row.`, "");
    }
    out.push(shown.length
        ? table(["#", "Timestamp", "Agent", "End user", "Route", "Status", "Decided by", "Request (redacted)", "Response (redacted)", "Row hash"], shown.map((r) => [
            String(r.id),
            mdEscape(r.timestamp),
            mdEscape(r.agent),
            r.endUser ? `${mdEscape(r.endUser)} (${r.endUserVerification})` : "—",
            `${mdEscape(r.method)} ${mdEscape(r.route)}`,
            mdEscape(r.status),
            r.approvedBy ? `approved: ${mdEscape(r.approvedBy)}` : r.rejectedBy ? `rejected: ${mdEscape(r.rejectedBy)}` : "—",
            snippet(r.request?.body ?? null),
            responseSnippet(r.response),
            r.rowHash ? `\`${r.rowHash.slice(0, 16)}…\`` : "unsealed",
        ]))
        : "No audit rows match the filters.", "");
    out.push("---", "", "All payloads were redacted before they were stored. Row hashes are truncated here; the JSON evidence bundle has them in full.", "");
    return out.join("\n");
}
