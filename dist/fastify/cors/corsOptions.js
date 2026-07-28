"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.corsOptions = corsOptions;
const policy_1 = require("../../core/cors/policy");
const DEFAULT_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
const DEFAULT_ALLOWED_HEADERS = [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Cache-Control',
    'Pragma',
    'Expires',
    'Accept',
    'Accept-Language',
    'Accept-Encoding',
    'Origin',
    'Referer',
    'User-Agent',
    'X-Bot-Key-Id',
    'X-Timestamp',
    'X-Nonce',
    'X-Signature',
    'X-Request-Id',
];
const DEFAULT_EXPOSED_HEADERS = [
    'RateLimit-Limit',
    'RateLimit-Remaining',
    'RateLimit-Reset',
];
const DEFAULT_OPTIONS_SUCCESS_STATUS = 200;
const DEFAULT_MAX_AGE_SECONDS = 86400;
/**
 * Build `@fastify/cors` options from the kit's fail-closed origin policy.
 *
 * The core policy is resolved ONCE here, at construction — so a
 * production-empty allowlist throws at BOOT (fail closed), not on the first
 * request. The `origin` callback is fixed by this module and always calls
 * `callback(null, <canonical string> | boolean)`; it is not part of
 * {@link CorsOptionsConfig}, so no consumer override can replace it. Every
 * other option is an overridable, purely non-security default
 * (methods/headers/credentials/maxAge/status).
 *
 * IMPORTANT: for an allowed origin this calls back with the CANONICAL
 * allowlist string (via {@link CorsPolicy.resolveAllowedOrigin}), never
 * `true` and never the raw incoming `Origin` header. `callback(null, true)`
 * would make `@fastify/cors` REFLECT the raw request Origin verbatim into
 * `Access-Control-Allow-Origin` — since request headers are attacker-
 * controlled, that would echo back arbitrary bytes for any origin string
 * that merely *normalizes* to an allowed one, rather than emitting the fixed
 * value the allowlist actually authorizes.
 */
function corsOptions(config) {
    const policy = (0, policy_1.resolveCorsPolicy)(config);
    return {
        credentials: config.credentials ?? true,
        methods: config.methods ?? DEFAULT_METHODS,
        allowedHeaders: config.allowedHeaders ?? DEFAULT_ALLOWED_HEADERS,
        exposedHeaders: config.exposedHeaders ?? DEFAULT_EXPOSED_HEADERS,
        optionsSuccessStatus: config.optionsSuccessStatus ?? DEFAULT_OPTIONS_SUCCESS_STATUS,
        maxAge: config.maxAge ?? DEFAULT_MAX_AGE_SECONDS,
        origin(origin, callback) {
            callback(null, policy.resolveAllowedOrigin(origin));
        },
    };
}
