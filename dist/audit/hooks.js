"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditFailureHook = auditFailureHook;
exports.auditRateLimitHook = auditRateLimitHook;
exports.auditDeniedHook = auditDeniedHook;
const buildAuditEvent_1 = require("./buildAuditEvent");
/**
 * Adapter for `createApiKeyAuth.onFailure` / signing verifier `onFailure`.
 * Records a `deny` (default) event carrying the failure reason. The returned
 * function matches `(req, reason) => void` and never throws.
 */
function auditFailureHook(buffer, action, outcome = 'deny', options = {}) {
    return (req, reason) => {
        try {
            // String(reason) can throw if reason has a hostile toString — guard it.
            let reasonStr;
            try {
                reasonStr = String(reason);
            }
            catch {
                reasonStr = 'unknown';
            }
            buffer.record((0, buildAuditEvent_1.buildAuditEvent)(req, { action, outcome, reason: reasonStr }, options));
        }
        catch {
            // Hooks are called from other middlewares' hot paths — never throw.
        }
    };
}
/**
 * Adapter for `createRateLimiter.onLimit`. Records a `deny` event tagging the
 * limiter key in meta. Matches `(req, key) => void`.
 */
function auditRateLimitHook(buffer, action, options = {}) {
    return (req, key) => {
        try {
            buffer.record((0, buildAuditEvent_1.buildAuditEvent)(req, { action, outcome: 'deny', reason: 'rate_limited', meta: { key } }, options));
        }
        catch {
            // never throw from a middleware hook
        }
    };
}
/**
 * Adapter for `requireScope.onDenied`. Records a `deny` event. Matches
 * `(req) => void`.
 */
function auditDeniedHook(buffer, action, options = {}) {
    return (req) => {
        try {
            buffer.record((0, buildAuditEvent_1.buildAuditEvent)(req, { action, outcome: 'deny', reason: 'scope_denied' }, options));
        }
        catch {
            // never throw from a middleware hook
        }
    };
}
