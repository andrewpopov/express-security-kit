"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireScope = requireScope;
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
/**
 * Guard-builder that runs a SERVICE-PROVIDED, SYNCHRONOUS predicate against
 * `req.securityContext`. It proceeds ONLY when the predicate returns the literal
 * boolean `true`; anything else denies with a generic 403:
 *  - `false` (or any non-`true` value, including a truthy object) → deny.
 *  - a thenable/Promise → MISUSE (predicates must be synchronous): denied and
 *    logged. Never `await`ed, so an async predicate can never let a request
 *    through on a truthy-Promise.
 *  - a thrown predicate → deny (fail closed).
 *
 * The kit ships only the mechanism — the predicate encodes the service's own
 * policy (stoki allowedActions, smarthome role gates, cairn org/project scope).
 * A predicate is responsible for handling an undefined context (e.g. requests
 * that ran the verifier in `optional` mode); returning false there denies.
 */
function requireScope(predicate, opts = {}) {
    const logger = opts.logger ?? consoleLogger;
    return (req, res, next) => {
        let result;
        try {
            result = predicate(req.securityContext, req);
        }
        catch {
            // A throwing policy predicate denies (fail closed).
            result = false;
        }
        // Guard against async-predicate misuse: a Promise is truthy but its real
        // value is unknown here. Treat it as a policy error and deny.
        if (result && typeof result.then === 'function') {
            logger.warn('[express-security-kit] requireScope predicate returned a Promise; ' +
                'predicates MUST be synchronous. Denying.');
            result = false;
        }
        // STRICT: only a literal `true` proceeds.
        if (result === true) {
            return next();
        }
        if (opts.onDenied) {
            try {
                const maybePromise = opts.onDenied(req);
                if (maybePromise &&
                    typeof maybePromise.then === 'function') {
                    maybePromise.catch((err) => logger.warn('[express-security-kit] onDenied hook rejected', err));
                }
            }
            catch (err) {
                logger.warn('[express-security-kit] onDenied hook threw', err);
            }
        }
        return res.status(403).json({
            error: { code: 'FORBIDDEN', message: 'Forbidden' },
        });
    };
}
