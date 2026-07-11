"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApiKeyAuth = createApiKeyAuth;
const verifyApiKey_1 = require("../../core/api-key/verifyApiKey");
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
/** Send a generic 401. The specific reason is NEVER leaked to the client. */
function unauthorized(res) {
    res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
    });
}
/** Send a generic 403. */
function forbidden(res) {
    res.status(403).json({
        error: { code: 'FORBIDDEN', message: 'Forbidden' },
    });
}
/**
 * Build an API-key authentication middleware.
 *
 * Auth FAILS CLOSED: any failure (missing/bad/expired/denied key, or an
 * unexpected error such as a throwing `lookup`) yields a GENERIC 401/403 and the
 * request does NOT proceed. This is the opposite of the rate limiter, which
 * fails open. Only the `onFailure` audit hook receives the specific reason.
 *
 * This is a thin middleware wrapper around {@link verifyApiKey}: it applies the
 * `optional`-passthrough policy and translates the verification outcome into an
 * HTTP response; the verification core lives in verifyApiKey.
 */
function createApiKeyAuth(config) {
    const logger = config.logger ?? consoleLogger;
    const fail = (req, res, reason, status) => {
        // An audit hook must never affect the auth decision, throw out, or leak an
        // unhandled rejection. Swallow sync throws and attach a .catch to promises.
        if (config.onFailure) {
            try {
                const maybePromise = config.onFailure(req, reason);
                if (maybePromise &&
                    typeof maybePromise.then === 'function') {
                    maybePromise.catch((err) => logger.warn('[express-security-kit] onFailure hook rejected', err));
                }
            }
            catch (err) {
                logger.warn('[express-security-kit] onFailure hook threw', err);
            }
        }
        if (status === 403)
            forbidden(res);
        else
            unauthorized(res);
    };
    return async (req, res, next) => {
        const outcome = await (0, verifyApiKey_1.verifyApiKey)(config, req);
        if (outcome.ok) {
            req.securityContext = outcome.context;
            return next();
        }
        // In optional mode, pass through ONLY a genuinely absent credential; a
        // present-but-invalid credential is a failed auth attempt and is rejected
        // even when optional.
        if (!outcome.present && config.optional) {
            return next();
        }
        return fail(req, res, outcome.reason, outcome.status);
    };
}
