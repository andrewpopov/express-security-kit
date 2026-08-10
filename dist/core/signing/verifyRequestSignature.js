"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRequestSignatureVerifierCore = createRequestSignatureVerifierCore;
const node_crypto_1 = require("node:crypto");
const hashers_1 = require("../api-key/hashers");
const signRequest_1 = require("./signRequest");
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
const DEFAULT_NONCE_FORMAT = /^[A-Za-z0-9:_-]{8,128}$/;
const HEX_64 = /^[a-f0-9]{64}$/i;
const SKEW_MIN_SECONDS = 30;
const SKEW_MAX_SECONDS = 900;
const DEFAULT_SKEW_SECONDS = 300;
function clampSkewSeconds(value) {
    const v = value ?? DEFAULT_SKEW_SECONDS;
    if (!Number.isFinite(v))
        return DEFAULT_SKEW_SECONDS;
    return Math.min(SKEW_MAX_SECONDS, Math.max(SKEW_MIN_SECONDS, v));
}
/** Log a warning without ever letting a throwing logger break verification. */
function safeWarn(config, message, err) {
    try {
        (config.logger ?? consoleLogger).warn(message, err);
    }
    catch {
        // A logger that throws must not prevent the fail-closed outcome.
    }
}
/**
 * Build the framework-agnostic HMAC request-signature verification engine.
 * `verify` mirrors the pre-carve Express middleware's control flow exactly
 * (see the ordering notes on each branch below) but performs NO framework
 * I/O — it never reads a request or writes a response. The adapter (Express,
 * Fastify, ...) does all framework-specific extraction (headers, body,
 * secret resolution, nonce scope) up front and translates the returned
 * outcome into an actual response.
 *
 * FAIL-CLOSED: any failure — unresolved secret, bad/absent
 * timestamp/nonce/signature, replay, or an unavailable nonce store — yields
 * `{ type: 'fail', reason }`. The specific reason is for the caller's own
 * failure/audit hook, never the client.
 *
 * The nonce is consumed ONLY AFTER the signature is proven valid, so an
 * attacker cannot burn a victim's nonce with an unsigned/forged request, and
 * a valid signature can be used at most once within the skew TTL.
 */
function createRequestSignatureVerifierCore(config) {
    const maxSkewSeconds = clampSkewSeconds(config.maxSkewSeconds);
    const maxSkewMs = maxSkewSeconds * 1000;
    const nonceFormat = config.nonceFormat ?? DEFAULT_NONCE_FORMAT;
    const requireRawBody = config.requireRawBody ?? false;
    const clock = config.now ?? Date.now;
    // Resolved fresh on every call (not hoisted out of `verify`) so a
    // `() => NonceStore` accessor sees whatever the caller's config currently
    // points at — see the late-binding note on `RequestSignatureVerifierConfigCore.nonceStore`.
    function resolveNonceStore() {
        return typeof config.nonceStore === 'function'
            ? config.nonceStore()
            : config.nonceStore;
    }
    async function verify(input) {
        try {
            // 1. Secret resolved FIRST, before any other check — matching the
            //    original middleware. Unresolved (undefined/empty) → fail closed.
            const secret = await input.secret();
            if (!secret) {
                return { type: 'fail', reason: 'no_secret' };
            }
            // 2. Timestamp: must be a finite, positive integer within skew.
            if (input.timestampHeader === undefined) {
                return { type: 'fail', reason: 'timestamp' };
            }
            const timestampMs = Number(input.timestampHeader);
            if (!Number.isFinite(timestampMs) || timestampMs <= 0) {
                return { type: 'fail', reason: 'timestamp' };
            }
            if (Math.abs(clock() - timestampMs) > maxSkewMs) {
                return { type: 'fail', reason: 'skew' };
            }
            // 3. Nonce: present and well-formed.
            const nonce = input.nonceHeader;
            if (nonce === undefined || !nonceFormat.test(nonce)) {
                return { type: 'fail', reason: 'nonce' };
            }
            // 4. Signature header: present and 64-hex.
            const signatureRaw = input.signatureHeader;
            if (signatureRaw === undefined || !HEX_64.test(signatureRaw)) {
                return { type: 'fail', reason: 'signature' };
            }
            const presented = signatureRaw.toLowerCase();
            // 4b. requireRawBody: the caller resolves what "has raw body" means for
            //     THIS request (bodyless-method exemption, custom extractor
            //     passthrough); the core only enforces the policy. `hasRawBody()`
            //     is pure (no side effects) but stays lazy — called only after
            //     every earlier check passes — to keep it, and `body()` right
            //     after it, in the same relative position the original code
            //     evaluated the equivalent checks.
            if (requireRawBody && !input.hasRawBody()) {
                return { type: 'fail', reason: 'no_raw_body' };
            }
            // 5. Body resolved now — only after requireRawBody has passed — then
            //    recompute the expected signature and timing-safe compare. A
            //    `bodySource` with side effects (or one that throws, e.g. on a
            //    circular object) must never run for a request that was always
            //    going to be rejected on an earlier check.
            const canonical = (0, signRequest_1.buildCanonicalString)({
                method: input.method,
                url: input.url,
                timestampMs,
                nonce,
                body: input.body(),
            });
            const expected = (0, node_crypto_1.createHmac)('sha256', secret).update(canonical).digest('hex');
            if (!(0, hashers_1.timingSafeEqualHex)(presented, expected)) {
                return { type: 'fail', reason: 'signature' };
            }
            // 6. Replay protection: nonceScope is resolved, and the nonce
            //    consumed, ONLY now that the signature is proven valid — a
            //    throwing `nonceScope` must never run against a malformed/forged
            //    request, and it must never turn a request's specific failure
            //    reason into a generic `error`. Store unavailable (throw) → FAIL
            //    CLOSED.
            const scope = input.nonceScope();
            // Typed as unknown on purpose: a custom store might violate the
            // contract and return something other than 'ok' | 'replay'; we defend
            // against that.
            let consumeResult;
            try {
                consumeResult = await resolveNonceStore().consume(scope, nonce, maxSkewMs);
            }
            catch (err) {
                safeWarn(config, '[express-security-kit] nonce store unavailable', err);
                return { type: 'fail', reason: 'store_error' };
            }
            if (consumeResult === 'replay') {
                return { type: 'fail', reason: 'replay' };
            }
            // Proceed ONLY on an explicit 'ok'. Any other value (undefined/false/
            // garbage from a misbehaving custom store that failed to record the
            // nonce) must NOT proceed — fail closed rather than allow a possible
            // replay.
            if (consumeResult !== 'ok') {
                safeWarn(config, '[express-security-kit] nonce store returned an unexpected result', {
                    result: consumeResult,
                });
                return { type: 'fail', reason: 'store_error' };
            }
            return { type: 'ok' };
        }
        catch (err) {
            // FAIL CLOSED on any unexpected error.
            safeWarn(config, '[express-security-kit] signing verifier error', err);
            return { type: 'fail', reason: 'error' };
        }
    }
    return { verify };
}
