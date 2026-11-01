"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerLicenseRoutes = registerLicenseRoutes;
const license_1 = require("../license");
const utils_1 = require("../utils");
/** License status (any signed-in user) and key management (admin only). */
function registerLicenseRoutes(router, ctx) {
    const { auth, license } = ctx;
    router.get("/license", async (_req, res) => {
        try {
            res.json(await license.resolveLicenseStatus());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "License status error", err, "Could not read the license status.");
        }
    });
    router.post("/license", async (req, res) => {
        if (!auth.requireAdmin(req, res))
            return;
        try {
            const licenseKey = req.body?.licenseKey;
            if (typeof licenseKey !== "string" || licenseKey.trim() === "") {
                (0, utils_1.sendError)(res, 400, "Bad Request", "licenseKey must be a MONT-... key.");
                return;
            }
            const result = (0, license_1.verifyLicenseKey)(licenseKey);
            if (!result.ok) {
                (0, utils_1.sendError)(res, 400, "Bad Request", result.reason);
                return;
            }
            await license.saveLicenseKey(licenseKey);
            res.json(await license.resolveLicenseStatus());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Save license error", err, "Could not save the license key.");
        }
    });
    router.delete("/license", async (req, res) => {
        if (!auth.requireAdmin(req, res))
            return;
        try {
            await license.removeLicenseKey();
            res.json(await license.resolveLicenseStatus());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Remove license error", err, "Could not remove the license key.");
        }
    });
    // Dev/test helper: ?state=expired (trial began 8 days ago) or ?state=active (trial begins now).
    // Also accepts { "state": "expired" | "active" } or { "expired": boolean } in the body.
    router.post("/license/simulate-trial-expiry", async (req, res) => {
        if (process.env.NODE_ENV === "production") {
            (0, utils_1.sendError)(res, 404, "Not Found", "Not available in production.");
            return;
        }
        if (!auth.requireAdmin(req, res))
            return;
        try {
            const body = (req.body ?? {});
            const state = typeof req.query.state === "string" ? req.query.state : body.state;
            let expired;
            if (state === "expired")
                expired = true;
            else if (state === "active")
                expired = false;
            else if (typeof body.expired === "boolean")
                expired = body.expired;
            else {
                (0, utils_1.sendError)(res, 400, "Bad Request", 'Use ?state=expired or ?state=active (or { "expired": true|false }).');
                return;
            }
            await license.simulateTrial(expired);
            res.json(await license.resolveLicenseStatus());
        }
        catch (err) {
            (0, utils_1.sendInternalError)(res, "Simulate trial error", err, "Could not change the trial state.");
        }
    });
}
