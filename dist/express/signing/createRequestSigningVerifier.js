"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRequestSigningVerifier = createRequestSigningVerifier;
const verifyRequestSignature_1 = require("../../core/signing/verifyRequestSignature");
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
/** First string value of a (possibly array) header. */
function headerValue(req, name) {
    const raw = req.headers?.[name.toLowerCase()];
    const value = Array.isArray(raw) ? raw[0] : raw;
    return typeof value === 'string' ? value : undefined;
}
/**
 * Default body extractor. Prefers the RAW received bytes (`req.rawBody`) so the
 * hashed content is byte-identical to what the client signed. GET/HEAD → ''.
 * Falls back to string/Buffer/JSON.stringify(object) when no rawBody exists —
 * but see the loud warning in the module docs: JSON re-serialization can differ
 * from the client's exact bytes and cause spurious signature failures.
 */
function defaultBodySource(req) {
    const method = (req.method ?? '').toUpperCase();
    if (method === 'GET' || method === 'HEAD')
        return '';
    const rawBody = req.rawBody;
    if (typeof rawBody === 'string')
        return rawBody;
    if (Buffer.isBuffer(rawBody))
        return rawBody.toString('utf8');
    const body = req.body;
    if (body === undefined || body === null)
        return '';
    if (typeof body === 'string')
        return body;
    if (Buffer.isBuffer(body))
        return body.toString('utf8');
    return JSON.stringify(body);
}
function defaultNonceScope(_req, ctx) {
    return ctx?.keyId ?? ctx?.principalId ?? 'global';
}
function unauthorized(res) {
    res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
    });
}
/**
 * OPT-IN HMAC request-signing + replay-protection middleware. FAIL-CLOSED: any
 * failure — unresolved secret, bad/absent timestamp/nonce/signature, replay, or
 * an unavailable nonce store — yields a GENERIC 401 and the request does NOT
 * proceed. The specific reason goes only to `onFailure`.
 *
 * This is a THIN adapter over {@link createRequestSignatureVerifierCore}: all
 * decision logic (ordering, fail-closed semantics, the nonce-consumed-after-
 * signature-proven rule) lives in the framework-agnostic core. This module
 * only does Express-specific extraction — reading headers, resolving the body
 * source, resolving the secret, deriving the nonce scope, and the
 * `requireRawBody` bodyless/custom-extractor exemption — and translates the
 * core's outcome into a response (`onFailure` + generic 401, or `next()`).
 */
function createRequestSigningVerifier(config) {
    const headerNames = {
        timestamp: config.headerNames?.timestamp ?? 'x-timestamp',
        nonce: config.headerNames?.nonce ?? 'x-nonce',
        signature: config.headerNames?.signature ?? 'x-signature',
    };
    const nonceScope = config.nonceScope ?? defaultNonceScope;
    const usingDefaultBodySource = config.bodySource === undefined;
    const bodySource = config.bodySource ?? defaultBodySource;
    const logger = config.logger ?? consoleLogger;
    const core = (0, verifyRequestSignature_1.createRequestSignatureVerifierCore)({
        maxSkewSeconds: config.maxSkewSeconds,
        nonceFormat: config.nonceFormat,
        // An accessor, not `config.nonceStore` directly, so a host that replaces
        // `config.nonceStore` on its own config object AFTER constructing this
        // middleware (store rotation/recovery) takes effect on the very next
        // request — the pre-carve middleware read `config.nonceStore` fresh on
        // every call, and this preserves that observable behaviour at zero cost.
        nonceStore: () => config.nonceStore,
        requireRawBody: config.requireRawBody,
        now: config.now,
        logger: config.logger,
    });
    /**
     * Whether the `requireRawBody` precondition is satisfied for this request:
     * only body-bearing methods (never GET/HEAD) using the DEFAULT body
     * extractor are subject to it — a custom `bodySource` participates as
     * provided and always reports satisfied, matching the pre-carve behaviour.
     */
    function hasRawBody(req) {
        if (!usingDefaultBodySource)
            return true;
        const method = (req.method ?? '').toUpperCase();
        if (method === 'GET' || method === 'HEAD')
            return true;
        const rawBody = req.rawBody;
        return typeof rawBody === 'string' || Buffer.isBuffer(rawBody);
    }
    const fail = (req, res, reason) => {
        if (config.onFailure) {
            try {
                const maybePromise = config.onFailure(req, reason);
                if (maybePromise &&
                    typeof maybePromise.then === 'function') {
                    maybePromise.catch((err) => logger.warn('[express-security-kit] signing onFailure rejected', err));
                }
            }
            catch (err) {
                logger.warn('[express-security-kit] signing onFailure threw', err);
            }
        }
        unauthorized(res);
    };
    return async (req, res, next) => {
        try {
            const ctx = req.securityContext;
            // `secret`, `body`, `nonceScope`, and `hasRawBody` are passed as
            // zero-argument closures over this request, NOT pre-computed here —
            // the core calls each at the exact point the pre-carve middleware did
            // (see the ordering doc on `RequestSignatureVerifyInput`). Evaluating
            // any of them eagerly, up front, would run a host's `bodySource` /
            // `nonceScope` (and their side effects, or a throw) for requests that
            // fail an earlier check and were never going to reach that point.
            const input = {
                method: req.method,
                url: req.originalUrl,
                timestampHeader: headerValue(req, headerNames.timestamp),
                nonceHeader: headerValue(req, headerNames.nonce),
                signatureHeader: headerValue(req, headerNames.signature),
                body: () => bodySource(req),
                secret: () => typeof config.secret === 'function'
                    ? config.secret(req, ctx)
                    : config.secret,
                nonceScope: () => nonceScope(req, ctx),
                hasRawBody: () => hasRawBody(req),
            };
            const outcome = await core.verify(input);
            if (outcome.type === 'fail') {
                return fail(req, res, outcome.reason);
            }
            return next();
        }
        catch (err) {
            // FAIL CLOSED on any unexpected error. A throwing secret resolver is
            // normally caught INSIDE core.verify() (it calls input.secret()) and
            // surfaces as outcome.reason === 'error' above; this catch is the
            // backstop for anything that can throw before core.verify() is even
            // reached (e.g. reading req.securityContext).
            logger.warn('[express-security-kit] signing verifier error', err);
            return fail(req, res, 'error');
        }
    };
}
