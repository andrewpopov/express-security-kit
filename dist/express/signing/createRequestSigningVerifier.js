"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRequestSigningVerifier = createRequestSigningVerifier;
const node_crypto_1 = require("node:crypto");
const hashers_1 = require("../../core/api-key/hashers");
const signRequest_1 = require("../../core/signing/signRequest");
const DEFAULT_NONCE_FORMAT = /^[A-Za-z0-9:_-]{8,128}$/;
const HEX_64 = /^[a-f0-9]{64}$/i;
const SKEW_MIN_SECONDS = 30;
const SKEW_MAX_SECONDS = 900;
const DEFAULT_SKEW_SECONDS = 300;
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
function clampSkewSeconds(value) {
    const v = value ?? DEFAULT_SKEW_SECONDS;
    if (!Number.isFinite(v))
        return DEFAULT_SKEW_SECONDS;
    return Math.min(SKEW_MAX_SECONDS, Math.max(SKEW_MIN_SECONDS, v));
}
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
 * The signed nonce is consumed AFTER the signature is proven valid and BEFORE
 * `next()`, so an attacker cannot burn a victim's nonce with an unsigned/forged
 * request, and a valid signature can be used at most once within the skew TTL.
 */
function createRequestSigningVerifier(config) {
    const maxSkewSeconds = clampSkewSeconds(config.maxSkewSeconds);
    const maxSkewMs = maxSkewSeconds * 1000;
    const nonceFormat = config.nonceFormat ?? DEFAULT_NONCE_FORMAT;
    const headerNames = {
        timestamp: config.headerNames?.timestamp ?? 'x-timestamp',
        nonce: config.headerNames?.nonce ?? 'x-nonce',
        signature: config.headerNames?.signature ?? 'x-signature',
    };
    const nonceScope = config.nonceScope ?? defaultNonceScope;
    const usingDefaultBodySource = config.bodySource === undefined;
    const bodySource = config.bodySource ?? defaultBodySource;
    const requireRawBody = config.requireRawBody ?? false;
    const clock = config.now ?? Date.now;
    const logger = config.logger ?? consoleLogger;
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
            // 1. Resolve the secret. Unresolved (undefined/empty) → fail closed.
            const secret = typeof config.secret === 'function'
                ? await config.secret(req, ctx)
                : config.secret;
            if (!secret) {
                return fail(req, res, 'no_secret');
            }
            // 2. Timestamp: must be a finite, positive integer within skew.
            const timestampRaw = headerValue(req, headerNames.timestamp);
            if (timestampRaw === undefined) {
                return fail(req, res, 'timestamp');
            }
            const timestampMs = Number(timestampRaw);
            if (!Number.isFinite(timestampMs) || timestampMs <= 0) {
                return fail(req, res, 'timestamp');
            }
            if (Math.abs(clock() - timestampMs) > maxSkewMs) {
                return fail(req, res, 'skew');
            }
            // 3. Nonce: present and well-formed.
            const nonce = headerValue(req, headerNames.nonce);
            if (nonce === undefined || !nonceFormat.test(nonce)) {
                return fail(req, res, 'nonce');
            }
            // 4. Signature header: present and 64-hex.
            const signatureRaw = headerValue(req, headerNames.signature);
            if (signatureRaw === undefined || !HEX_64.test(signatureRaw)) {
                return fail(req, res, 'signature');
            }
            const presented = signatureRaw.toLowerCase();
            // 4b. requireRawBody: only for body-bearing methods (never GET/HEAD),
            // and only when using the DEFAULT body extractor — a custom bodySource
            // participates as provided.
            if (requireRawBody && usingDefaultBodySource) {
                const method = (req.method ?? '').toUpperCase();
                const bodyless = method === 'GET' || method === 'HEAD';
                if (!bodyless) {
                    const rawBody = req.rawBody;
                    const hasRawBody = typeof rawBody === 'string' || Buffer.isBuffer(rawBody);
                    if (!hasRawBody) {
                        return fail(req, res, 'no_raw_body');
                    }
                }
            }
            // 5. Recompute the expected signature and timing-safe compare.
            const canonical = (0, signRequest_1.buildCanonicalString)({
                method: req.method,
                url: req.originalUrl,
                timestampMs,
                nonce,
                body: bodySource(req),
            });
            const expected = (0, node_crypto_1.createHmac)('sha256', secret)
                .update(canonical)
                .digest('hex');
            if (!(0, hashers_1.timingSafeEqualHex)(presented, expected)) {
                return fail(req, res, 'signature');
            }
            // 6. Replay protection: consume the nonce ONLY now that the signature is
            //    proven valid. Store unavailable (throw) → FAIL CLOSED.
            const scope = nonceScope(req, ctx);
            // Typed as unknown on purpose: a custom store might violate the contract
            // and return something other than 'ok' | 'replay'; we defend against that.
            let consumeResult;
            try {
                consumeResult = await config.nonceStore.consume(scope, nonce, maxSkewMs);
            }
            catch (err) {
                logger.warn('[express-security-kit] nonce store unavailable', err);
                return fail(req, res, 'store_error');
            }
            if (consumeResult === 'replay') {
                return fail(req, res, 'replay');
            }
            // Proceed ONLY on an explicit 'ok'. Any other value (undefined/false/
            // garbage from a misbehaving custom store that failed to record the
            // nonce) must NOT proceed — fail closed rather than allow a possible
            // replay.
            if (consumeResult !== 'ok') {
                logger.warn('[express-security-kit] nonce store returned an unexpected result', { result: consumeResult });
                return fail(req, res, 'store_error');
            }
            return next();
        }
        catch (err) {
            // FAIL CLOSED on any unexpected error.
            logger.warn('[express-security-kit] signing verifier error', err);
            return fail(req, res, 'error');
        }
    };
}
