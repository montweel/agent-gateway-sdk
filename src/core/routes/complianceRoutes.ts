import type { Response, Router } from "express";
import type { GatewayContext } from "../context";
import type { AuthenticatedRequest, AuditConfig } from "../types";
import { sendError, sendInternalError } from "../utils";
import { cleanRedactKeys } from "../config";
import {
  COMPLIANCE_TEMPLATES,
  KNOWN_FRAMEWORKS,
  cleanFrameworks,
  findComplianceTemplate,
  mergeRedactKeys,
  mergeTemplateRules,
} from "../complianceTemplates";
import { buildEvidenceBundle, bundleToJson, bundleToMarkdown } from "../evidencePack";
import { actorOf, readScope, requireWorkspace, sendLicenseRequired } from "./scope";

/**
 *   GET  /compliance/templates          built-in industry templates + the active one
 *   POST /compliance/apply-template     { template, includeRules?, frameworks?, redactKeys? } (admin)
 *                                       merges the template's redact keys into audit.redactKeys and,
 *                                       with includeRules, adds its REQUIRE_APPROVAL rules to the
 *                                       selected workspace without overriding existing decisions
 *   GET  /audit/export-pack             Auditor Evidence Pack (Pro): ?format=report|json&from&to&agentName&endUser
 */
export function registerComplianceRoutes(router: Router, ctx: GatewayContext): void {
  router.get("/compliance/templates", (_req: AuthenticatedRequest, res: Response) => {
    const audit = ctx.config.load().audit;
    res.json({
      templates: COMPLIANCE_TEMPLATES,
      knownFrameworks: KNOWN_FRAMEWORKS,
      activeTemplate: audit.activeTemplate ?? null,
      complianceFrameworks: audit.complianceFrameworks ?? [],
    });
  });

  router.post("/compliance/apply-template", async (req: AuthenticatedRequest, res: Response) => {
    if (req.user?.role !== "admin") {
      sendError(res, 403, "Forbidden", "Only administrators can apply compliance templates.");
      return;
    }
    const body = (req.body ?? {}) as { template?: unknown; includeRules?: unknown; frameworks?: unknown; redactKeys?: unknown };
    const template = typeof body.template === "string" ? findComplianceTemplate(body.template) : undefined;
    if (!template) {
      sendError(res, 400, "Bad Request", `template must be one of: ${COMPLIANCE_TEMPLATES.map((t) => t.id).join(", ")}.`);
      return;
    }
    if (body.includeRules !== undefined && typeof body.includeRules !== "boolean") {
      sendError(res, 400, "Bad Request", "includeRules must be true or false.");
      return;
    }
    let frameworks: string[] | null = null;
    if (body.frameworks !== undefined) {
      frameworks = cleanFrameworks(body.frameworks);
      if (frameworks === null) {
        sendError(res, 400, "Bad Request", "frameworks must be a list of short tags (letters, digits, spaces, . - /; at most 32 characters each).");
        return;
      }
    }
    let extraKeys: string[] = [];
    if (body.redactKeys !== undefined) {
      if (!Array.isArray(body.redactKeys) || !body.redactKeys.every((k) => typeof k === "string")) {
        sendError(res, 400, "Bad Request", "redactKeys must be a list of strings.");
        return;
      }
      extraKeys = cleanRedactKeys(body.redactKeys) ?? [];
    }
    const ws = body.includeRules ? requireWorkspace(ctx, req, res) : null;
    if (ws === undefined) return;

    try {
      const config = ctx.config.load();
      const merged = mergeRedactKeys(config.audit.redactKeys, [...template.redactKeys, ...extraKeys]);
      const audit: AuditConfig = {
        ...config.audit,
        redactKeys: cleanRedactKeys(merged.keys) ?? config.audit.redactKeys,
        activeTemplate: template.id,
        complianceFrameworks: frameworks ?? (template.id === "custom" ? (config.audit.complianceFrameworks ?? []) : template.frameworks),
      };

      let rules: { added: string[]; skipped: Array<{ key: string; reason: string }>; workspace: string } | null = null;
      if (ws) {
        const result = mergeTemplateRules(ctx.workspaces.rules(ws.id), template, (method, path) => ctx.workspaces.lookupEntry(ws.id, method, path));
        if (result.added.length > 0) await ctx.workspaces.saveRules(ws.id, result.rules);
        rules = { added: result.added, skipped: result.skipped, workspace: ws.slug };
      }
      // Rules first: if saving them fails, the redaction profile is not half-applied either.
      ctx.config.save({ ...config, audit });
      res.json({ success: true, template: template.id, addedRedactKeys: merged.added, rules, config: { audit: ctx.config.load().audit } });
    } catch (err) {
      sendInternalError(res, "Apply template error", err, "Could not apply the compliance template.");
    }
  });

  router.get("/audit/export-pack", async (req: AuthenticatedRequest, res: Response) => {
    if (!ctx.license.current().features.auditVerification) {
      sendLicenseRequired(res, "auditVerification", "The Auditor Evidence Pack is a Mont Pro feature. Activate a Pro or Agency key to export it.");
      return;
    }
    const scoped = readScope(ctx, req, res);
    if (scoped === undefined) return;
    const q = req.query;
    const text = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : null);
    const format = text(q.format) ?? "report";
    if (format !== "report" && format !== "json") {
      sendError(res, 400, "Bad Request", 'format must be "report" or "json".');
      return;
    }
    const dates: Record<"from" | "to", string | null> = { from: null, to: null };
    for (const k of ["from", "to"] as const) {
      const v = text(q[k]);
      if (v === null) continue;
      const d = new Date(v);
      if (Number.isNaN(d.getTime())) {
        sendError(res, 400, "Bad Request", `${k} must be a date or ISO timestamp.`);
        return;
      }
      dates[k] = d.toISOString();
    }
    if (dates.from && dates.to && dates.from > dates.to) {
      sendError(res, 400, "Bad Request", "from must be before to.");
      return;
    }
    const agentName = text(q.agentName);
    const endUser = text(q.endUser);
    if ((agentName?.length ?? 0) > 256 || (endUser?.length ?? 0) > 256) {
      sendError(res, 400, "Bad Request", "agentName and endUser must be at most 256 characters.");
      return;
    }

    try {
      const bundle = await buildEvidenceBundle(ctx, scoped, { ...dates, agentName, endUser }, actorOf(req));
      const day = new Date().toISOString().slice(0, 10);
      const ws = scoped ? `-${scoped.slug}` : "";
      if (format === "json") {
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="mont-auditor-evidence${ws}-${day}.json"`);
        res.send(bundleToJson(bundle));
      } else {
        res.setHeader("Content-Type", "text/markdown; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="mont-auditor-report${ws}-${day}.md"`);
        res.send(bundleToMarkdown(bundle));
      }
    } catch (err) {
      sendInternalError(res, "Evidence pack error", err, "Could not build the auditor evidence pack.");
    }
  });
}
