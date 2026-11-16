"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerComplianceRoutes = registerComplianceRoutes;
const utils_1 = require("../utils");
const config_1 = require("../config");
const complianceTemplates_1 = require("../complianceTemplates");
const evidencePack_1 = require("../evidencePack");
const scope_1 = require("./scope");
/**
 *   GET  /compliance/templates          built-in industry templates + the active one
 *   POST /compliance/apply-template     { template, includeRules?, frameworks?, redactKeys? } (admin)
 *                                       merges the template's redact keys into audit.redactKeys and,
 *                                       with includeRules, adds its REQUIRE_APPROVAL rules to the
 *                                       selected workspace without overriding existing decisions
 *   GET  /audit/export-pack             Auditor Evidence Pack (Pro): ?format=report|json&from&to&agentName&endUser
 */
function registerComplianceRoutes(router, ctx) {
    router.get("/compliance/templates", (_req, res) => {
        const audit = ctx.config.load().audit;
        res.json({
            templates: complianceTemplates_1.COMPLIANCE_TEMPLATES,
            knownFrameworks: complianceTemplates_1.KNOWN_FRAMEWORKS,
            activeTemplate: audit.activeTemplate ?? null,
            complianceFrameworks: audit.complianceFrameworks ?? [],
        });
    });
    router.post("/compliance/apply-template", async (req, res) => {
        if (req.user?.role !== "admin") {
            (0, utils_1.sendError)(res, 403, "Forbidden", "Only administrators can apply compliance templates.");
            return;
        }
        const body = (req.body ?? {});
        const template = typeof body.template === "string" ? (0, complianceTemplates_1.findComplianceTemplate)(body.template) : undefined;
        if (!template) {
            (0, utils_1.sendError)(res, 400, "Bad Request", `template must be one of: ${complianceTemplates_1.COMPLIANCE_TEMPLATES.map((t) => t.id).join(", ")}.`);
            return;
        }
        if (body.includeRules !== undefined && typeof body.includeRules !== "boolean") {
            (0, utils_1.sendError)(res, 400, "Bad Request", "includeRules must be true or false.");
            return;
        }
        let frameworks = null;
        if (body.frameworks !== undefined) {
            frameworks = (0, complianceTemplates_1.cleanFrameworks)(body.frameworks);
            if (frameworks === null) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "frameworks must be a list of short tags (letters, digits, spaces, . - /; at most 32 characters each).");
                return;
            }
        }
        let extraKeys = [];
        if (body.redactKeys !== undefined) {
            if (!Array.isArray(body.redactKeys) || !body.redactKeys.every((k) => typeof k === "string")) {
                (0, utils_1.sendError)(res, 400, "Bad Request", "redactKeys must be a list of strings.");
                return;
            }
            extraKeys = (0, config_1.cleanRedactKeys)(body.redactKeys) ?? [];
        }
        const ws = body.includeRules ? (0, scope_1.requireWorkspace)(ctx, req, res) : null;
        if (ws === undefined)
            return;
        try {
            const config = ctx.config.load();
            const merged = (0, complianceTemplates_1.mergeRedactKeys)(config.audit.redactKeys, [...template.redactKeys, ...extraKeys]);
            const audit = {
                ...config.audit,
                redactKeys: (0, config_1.cleanRedactKeys)(merged.keys) ?? config.audit.redactKeys,
                activeTemplate: template.id,
                complianceFrameworks: frameworks ?? (template.id === "custom" ? (config.audit.complianceFrameworks ?? []) : template.frameworks),
            };
            let rules = null;
            if (ws) {
                const result = (0, complianceTemplates_1.mergeTemplateRules)(ctx.workspaces.rules(ws.id), template, (method, path) => ctx.workspaces.lookupEntry(ws.id, method, path));
                if (result.added.length > 0)
                    await ctx.workspaces.saveRules(ws.id, result.rules);
                rules = { added: result.added, skipped: result.skipped, workspace: ws.slug };
            }
            // Rules first: if saving them fails, the redaction profile is not half-applied either.
            ctx.config.save({ ...config, audit });
            res.json({ success: true, template: template.id, addedRedactKeys: merged.added, rules, config: { audit: ctx.config.load().audit } });
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Apply template error", err, "Could not apply the compliance template.");
        }
    });
    router.get("/audit/export-pack", async (req, res) => {
        if (!ctx.license.current().features.auditVerification) {
            (0, scope_1.sendLicenseRequired)(res, "auditVerification", "The Auditor Evidence Pack is a Mont Pro feature. Activate a Pro or Agency key to export it.");
            return;
        }
        const scoped = (0, scope_1.readScope)(ctx, req, res);
        if (scoped === undefined)
            return;
        const q = req.query;
        const text = (v) => (typeof v === "string" && v.trim() !== "" ? v.trim() : null);
        const format = text(q.format) ?? "report";
        if (format !== "report" && format !== "json") {
            (0, utils_1.sendError)(res, 400, "Bad Request", 'format must be "report" or "json".');
            return;
        }
        const dates = { from: null, to: null };
        for (const k of ["from", "to"]) {
            const v = text(q[k]);
            if (v === null)
                continue;
            const d = new Date(v);
            if (Number.isNaN(d.getTime())) {
                (0, utils_1.sendError)(res, 400, "Bad Request", `${k} must be a date or ISO timestamp.`);
                return;
            }
            dates[k] = d.toISOString();
        }
        if (dates.from && dates.to && dates.from > dates.to) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "from must be before to.");
            return;
        }
        const agentName = text(q.agentName);
        const endUser = text(q.endUser);
        if ((agentName?.length ?? 0) > 256 || (endUser?.length ?? 0) > 256) {
            (0, utils_1.sendError)(res, 400, "Bad Request", "agentName and endUser must be at most 256 characters.");
            return;
        }
        try {
            const bundle = await (0, evidencePack_1.buildEvidenceBundle)(ctx, scoped, { ...dates, agentName, endUser }, (0, scope_1.actorOf)(req));
            const day = new Date().toISOString().slice(0, 10);
            const ws = scoped ? `-${scoped.slug}` : "";
            if (format === "json") {
                res.setHeader("Content-Type", "application/json; charset=utf-8");
                res.setHeader("Content-Disposition", `attachment; filename="mont-auditor-evidence${ws}-${day}.json"`);
                res.send((0, evidencePack_1.bundleToJson)(bundle));
            }
            else {
                res.setHeader("Content-Type", "text/markdown; charset=utf-8");
                res.setHeader("Content-Disposition", `attachment; filename="mont-auditor-report${ws}-${day}.md"`);
                res.send((0, evidencePack_1.bundleToMarkdown)(bundle));
            }
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Evidence pack error", err, "Could not build the auditor evidence pack.");
        }
    });
}
