"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createWebhookVerifier = createWebhookVerifier;
const verify_1 = require("../../core/webhook/verify");
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
/**
 * Reasons that mean "we can't currently make a decision" (missing/invalid
 * configured credential, or a nonce-store/resolver outage) → 503. Every other
 * reason means "this specific request failed verification" → 401. Matches the
 * design doc's C3 status mapping.
 */
const SERVICE_UNAVAILABLE_REASONS = new Set([
    'missing_secret',
    'missing_public_key',
    'store_unavailable',
]);
function statusForReason(reason) {
    return SERVICE_UNAVAILABLE_REASONS.has(reason) ? 503 : 401;
}
/** Send a generic 401. The specific reason is NEVER leaked to the client. */
function unauthorized(res) {
    res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
    });
}
/** Send a generic 503. The specific reason is NEVER leaked to the client. */
function serviceUnavailable(res) {
    res.status(503).json({
        error: { code: 'SERVICE_UNAVAILABLE', message: 'Service unavailable' },
    });
}
function defaultRawBody(req) {
    return req.rawBody;
}
/**
 * Build an inbound-webhook signature verification middleware, wrapping the
 * framework-agnostic {@link verifyWebhookSignature}.
 *
 * FAILS CLOSED: any verification failure — or an unexpected throw anywhere in
 * this middleware — yields a GENERIC response and the request does NOT
 * proceed. The specific {@link WebhookVerifyReason} is passed ONLY to
 * `onFailure`, never to the client, so the response never leaks whether a
 * secret/key exists or which check failed.
 */
function createWebhookVerifier(config) {
    const logger = config.logger ?? consoleLogger;
    const getRawBody = config.rawBody ?? defaultRawBody;
    const fail = (req, res, reason, status) => {
        // An audit hook must never affect the decision, throw out, or leak an
        // unhandled rejection. Swallow sync throws and attach a .catch to promises.
        if (config.onFailure) {
            try {
                const maybePromise = config.onFailure(req, reason);
                if (maybePromise &&
                    typeof maybePromise.then === 'function') {
                    maybePromise.catch((err) => logger.warn('[express-security-kit] webhook onFailure hook rejected', err));
                }
            }
            catch (err) {
                logger.warn('[express-security-kit] webhook onFailure hook threw', err);
            }
        }
        if (status === 503)
            serviceUnavailable(res);
        else
            unauthorized(res);
    };
    return async (req, res, next) => {
        try {
            const rawBody = getRawBody(req);
            const headers = req.headers;
            const outcome = await (0, verify_1.verifyWebhookSignature)({ rawBody, headers, config });
            if (outcome.ok) {
                return next();
            }
            return fail(req, res, outcome.reason, statusForReason(outcome.reason));
        }
        catch (err) {
            // FAIL CLOSED on any unexpected error (e.g. a throwing `rawBody`
            // extractor). Treated as a config/resolver-class failure (C3) — 503,
            // reported to onFailure as `store_unavailable`, the closest existing
            // "system trouble, not a per-request forgery" reason in the union.
            logger.warn('[express-security-kit] webhook verifier error', err);
            return fail(req, res, 'store_unavailable', 503);
        }
    };
}
