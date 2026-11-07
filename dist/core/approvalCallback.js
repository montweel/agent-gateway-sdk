"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApprovalCallbackRouter = createApprovalCallbackRouter;
const express_1 = __importDefault(require("express"));
const constants_1 = require("./constants");
const approvalSigning_1 = require("./approvalSigning");
const rateLimit_1 = require("./rateLimit");
const utils_1 = require("./utils");
/**
 * One-click approvals from a phone (Slack / Telegram / webhook links).
 *
 *   GET  /_mont/approvals/:id/confirm?d=APPROVE&exp=...&sig=...   -> confirmation page (changes nothing)
 *   POST /_mont/approvals/:id/confirm  (same fields, form-encoded)  -> performs the decision
 *
 * GET is side-effect free on purpose: chat apps fetch links to build previews, and a GET
 * that approved would let a link preview approve an action nobody looked at.
 * Both steps verify the HMAC-SHA256 signature, the expiry, and that the action is still PENDING.
 * Bad signatures are counted per client IP and locked out after CALLBACK_MAX_FAILURES.
 */
const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
function page(res, status, title, inner) {
    res.status(status);
    res.setHeader("Content-Security-Policy", PAGE_CSP);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Robots-Tag", "noindex, nofollow");
    res.type("html").send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Mont Gateway</title>
<style>
  body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0}
  main{max-width:560px;margin:0 auto;padding:24px 16px}
  h1{font-size:20px;margin:0 0 4px} .muted{color:#94a3b8;font-size:13px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:16px;margin-top:16px}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .m{font:600 12px ui-monospace,Menlo,monospace;background:#334155;border-radius:6px;padding:2px 8px}
  code{font:13px ui-monospace,Menlo,monospace;word-break:break-all}
  pre{background:#020617;border-radius:10px;padding:12px;overflow:auto;font:12px/1.5 ui-monospace,Menlo,monospace;max-height:320px}
  .risk{background:#451a03;border:1px solid #b45309;color:#fde68a;border-radius:10px;padding:10px;margin-top:12px;font-size:13px}
  button{width:100%;border:0;border-radius:12px;padding:14px;font-size:16px;font-weight:700;margin-top:16px;cursor:pointer}
  .approve{background:#059669;color:#fff} .reject{background:#dc2626;color:#fff}
  .ok{color:#6ee7b7} .bad{color:#fca5a5}
</style></head><body><main>${inner}</main></body></html>`);
}
function readFields(req, source) {
    const one = (v) => (typeof v === "string" ? v : Array.isArray(v) && typeof v[0] === "string" ? v[0] : "");
    return {
        id: Number(req.params.id),
        decision: (0, approvalSigning_1.parseCallbackDecision)(one(source.d)),
        exp: Number(one(source.exp)),
        sig: one(source.sig),
    };
}
function createApprovalCallbackRouter(ctx) {
    const router = express_1.default.Router();
    const urlencoded = express_1.default.urlencoded({ extended: false, limit: "4kb", parameterLimit: 10 });
    router.use(constants_1.APPROVAL_CALLBACK_PREFIX, (_req, res, next) => {
        ctx.ready.then(() => next(), () => page(res, 503, "Unavailable", `<h1 class="bad">Gateway unavailable</h1><p>The gateway database is not ready.</p>`));
    });
    /** Verifies a link and loads its action. Sends the error page and returns null on any failure. */
    async function authorize(req, res, f) {
        const ipKey = `callback:${(0, rateLimit_1.bucketIp)(req.ip ?? req.socket.remoteAddress ?? "unknown")}`;
        const lock = ctx.limiters.checkLoginLockout(ipKey, constants_1.CALLBACK_MAX_FAILURES);
        if (lock.locked) {
            res.setHeader("Retry-After", String(lock.retryAfterSec));
            page(res, 429, "Too many attempts", `<h1 class="bad">Too many invalid links</h1><p>Try again in ${lock.retryAfterSec} seconds.</p>`);
            return null;
        }
        if (f.decision === null || !Number.isInteger(f.id) || f.id < 0) {
            ctx.limiters.recordLoginFailure(ipKey);
            page(res, 400, "Invalid link", `<h1 class="bad">Invalid link</h1><p>This approval link is malformed.</p>`);
            return null;
        }
        const secret = ctx.settings.approvalSigningSecret();
        if (f.id === 0) {
            // The Setup tab's test notification: signed with a fixed queued-at it cannot know, so test
            // links only prove that the phone can reach this URL. They never touch an action.
            return "test";
        }
        const row = await ctx.db.get("SELECT * FROM pending_actions WHERE id = ?", [f.id]);
        const verdict = (0, approvalSigning_1.verifyApprovalLink)(secret, { id: f.id, decision: f.decision, exp: f.exp, queuedAt: row?.timestamp ?? "" }, f.sig);
        if (!row || !verdict.ok) {
            if (!verdict.ok && verdict.reason !== "expired")
                ctx.limiters.recordLoginFailure(ipKey);
            const msg = !verdict.ok && verdict.reason === "expired" ? "This approval link has expired." : "This approval link is not valid.";
            page(res, 403, "Link rejected", `<h1 class="bad">Link rejected</h1><p>${msg}</p><p class="muted">Open the admin console to decide this request.</p>`);
            return null;
        }
        return row;
    }
    function summary(row) {
        let pretty = row.body ?? "";
        let risks = [];
        try {
            const parsed = row.body ? JSON.parse(row.body) : null;
            pretty = parsed === null ? "(no body)" : JSON.stringify(parsed, null, 2);
            risks = (0, utils_1.findHighRiskFields)(parsed);
        }
        catch {
            // keep raw text
        }
        const caller = [
            row.agent_key ? `key “${row.agent_key}”${row.agent_key_prefix ? ` (${row.agent_key_prefix}…)` : ""}` : null,
            row.caller_ip ? `IP ${row.caller_ip}` : null,
        ]
            .filter(Boolean)
            .join(" · ");
        return `
      <div class="card">
        <div class="row"><span class="m">#${row.id}</span><span class="m">${esc(row.method)}</span><code>${esc(row.path)}</code></div>
        <p class="muted">Queued ${esc(row.timestamp)}${caller ? ` · ${esc(caller)}` : ""}${row.matched_policy ? ` · matched ${esc(row.matched_policy)}` : ""}</p>
        ${row.agent_reason ? `<p><b>Agent's reason:</b> ${esc(row.agent_reason)}</p>` : ""}
        ${risks.length ? `<div class="risk"><b>High-risk fields</b><br>${risks.map((r) => `<code>${esc(r.path)}</code> = <code>${esc(JSON.stringify(r.value))}</code>`).join("<br>")}</div>` : ""}
        <pre>${esc(pretty)}</pre>
      </div>`;
    }
    router.get(`${constants_1.APPROVAL_CALLBACK_PREFIX}/:id/confirm`, async (req, res) => {
        try {
            const f = readFields(req, req.query);
            const row = await authorize(req, res, f);
            if (row === null)
                return;
            if (row === "test") {
                page(res, 200, "Test link", `<h1 class="ok">It works</h1><p>Your phone can reach the gateway. Real notifications will open a confirmation page like this one.</p>`);
                return;
            }
            if (row.status !== "PENDING") {
                page(res, 409, "Already decided", `<h1>Already ${esc(row.status.toLowerCase())}</h1>${summary(row)}`);
                return;
            }
            const approve = f.decision === "APPROVE";
            page(res, 200, approve ? "Approve request" : "Reject request", `<h1>${approve ? "Approve" : "Reject"} this AI agent request?</h1>
         <p class="muted">Review the payload below. Nothing happens until you tap the button.</p>
         ${summary(row)}
         <form method="post" action="${esc(`${constants_1.APPROVAL_CALLBACK_PREFIX}/${row.id}/confirm`)}">
           <input type="hidden" name="d" value="${esc(f.decision ?? "")}">
           <input type="hidden" name="exp" value="${esc(String(f.exp))}">
           <input type="hidden" name="sig" value="${esc(f.sig)}">
           <button class="${approve ? "approve" : "reject"}" type="submit">${approve ? "✅ Approve & execute" : "⛔ Reject"}</button>
         </form>`);
        }
        catch (err) {
            console.error("Approval link error:", err);
            page(res, 500, "Error", `<h1 class="bad">Something went wrong</h1><p>Nothing was approved. Use the admin console.</p>`);
        }
    });
    router.post(`${constants_1.APPROVAL_CALLBACK_PREFIX}/:id/confirm`, urlencoded, async (req, res) => {
        try {
            const f = readFields(req, (req.body ?? {}));
            const row = await authorize(req, res, f);
            if (row === null)
                return;
            if (row === "test") {
                page(res, 200, "Test link", `<h1 class="ok">It works</h1><p>This was a test; nothing was changed.</p>`);
                return;
            }
            const result = await ctx.approvals.decide(row.id, f.decision, "mobile-link");
            const body = result.body;
            if (result.status >= 200 && result.status < 300) {
                page(res, 200, "Done", `<h1 class="ok">${body.status === "APPROVED" ? "Approved and executed" : "Rejected"}</h1>
           <p>Request #${row.id} ${body.status === "APPROVED" ? `was executed${body.replayStatus !== undefined ? ` (target replied HTTP ${body.replayStatus})` : ""}` : "will not run"}.</p>`);
            }
            else {
                page(res, result.status, "Not done", `<h1 class="bad">Not done</h1><p>${esc(body.message ?? "The decision could not be applied.")}</p>`);
            }
        }
        catch (err) {
            console.error("Approval link error:", err);
            page(res, 500, "Error", `<h1 class="bad">Something went wrong</h1><p>The decision may not have been applied. Check the admin console.</p>`);
        }
    });
    return router;
}
