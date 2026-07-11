"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyWebhookSignature = verifyWebhookSignature;
const node_crypto_1 = require("node:crypto");
const signRequest_1 = require("../signing/signRequest");
function collectMatches(headers, name) {
    const lower = name.toLowerCase();
    const matches = [];
    for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === lower) {
            matches.push(headers[key]);
        }
    }
    return matches;
}
/**
 * Case-insensitive single-value header read, TRIMMED. Returns `undefined` —
 * treated identically to "absent" by every caller — when the header is
 * genuinely absent OR ambiguous: present as an array (duplicate headers some
 * frameworks surface as `string[]`), present under more than one case-variant
 * key simultaneously, or a value containing a raw comma (the byte sequence
 * Node's http module uses to join genuinely-duplicated headers into one
 * string). None of the values this verifier reads (hex signatures, decimal
 * timestamps) legitimately contain a comma, so any comma is treated as an
 * ambiguous duplicate rather than guessed at (C8: reject, don't guess).
 */
function readHeaderTrimmed(headers, name) {
    const matches = collectMatches(headers, name);
    if (matches.length !== 1)
        return undefined;
    const value = matches[0];
    if (typeof value !== 'string')
        return undefined;
    const trimmed = value.trim();
    if (trimmed.length === 0)
        return undefined;
    if (trimmed.includes(','))
        return undefined;
    return trimmed;
}
/**
 * Case-insensitive single-value header read, UNTRIMMED. Used ONLY to pull the
 * raw bytes of the ed25519 timestamp header for message construction (C5):
 * the signer computed their signature over the EXACT bytes of that header, so
 * the verifier must reproduce those exact bytes rather than a
 * whitespace-normalized copy — otherwise a request whose timestamp header was
 * tampered with (extra whitespace, a re-serialized/leading-zero variant)
 * would be silently normalized back to the originally-signed value instead of
 * failing signature verification. Still rejects array/multi-key/comma-joined
 * ambiguity, same as {@link readHeaderTrimmed}.
 */
function readHeaderRaw(headers, name) {
    const matches = collectMatches(headers, name);
    if (matches.length !== 1)
        return undefined;
    const value = matches[0];
    if (typeof value !== 'string')
        return undefined;
    if (value.length === 0)
        return undefined;
    if (value.includes(','))
        return undefined;
    return value;
}
function buildHeaderReader(headers) {
    return (name) => readHeaderTrimmed(headers, name);
}
function fail(reason) {
    return { ok: false, reason };
}
const OK = { ok: true };
// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
function toBuffer(body) {
    return Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
}
const HEX_CHARS_EVEN_LENGTH = /^(?:[0-9a-fA-F]{2})+$/;
/**
 * Run the replay-protection step shared by both schemes: derive the
 * (authenticated) replay id, resolve the scope, and atomically consume it.
 * Only ever reached AFTER the signature has been verified (C4) — callers
 * must not invoke this earlier.
 */
async function consumeReplay(replay, headers, rawBody, defaultReplayId) {
    const replayId = replay.idFromVerifiedBody
        ? replay.idFromVerifiedBody(rawBody)
        : defaultReplayId;
    if (!replayId) {
        return fail('missing_replay_id');
    }
    let scope;
    try {
        scope = typeof replay.scope === 'function' ? await replay.scope(headers) : replay.scope;
    }
    catch {
        // A throwing scope resolver leaves replay protection unusable — fail
        // closed exactly like a store outage, never silently skip the check.
        return fail('store_unavailable');
    }
    try {
        const result = await replay.store.consume(scope, replayId, replay.ttlMs);
        if (result === 'replay')
            return fail('replay');
    }
    catch {
        return fail('store_unavailable');
    }
    return null;
}
// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------
async function resolveHmacSecret(config, headers) {
    try {
        const value = typeof config.secret === 'function' ? await config.secret(headers) : config.secret;
        return value && value.length > 0 ? value : undefined;
    }
    catch {
        return undefined;
    }
}
async function verifyHmacSha256(config, rawBody, rawHeaders) {
    const headers = buildHeaderReader(rawHeaders);
    // 1. Resolve credential FIRST (C4) — an unresolvable secret must never let
    //    the request reach signature comparison or the nonce store.
    const secret = await resolveHmacSecret(config, headers);
    if (secret === undefined)
        return fail('missing_secret');
    // 2. Read + strictly validate the signed inputs (signature header, body).
    const signatureHeaderName = config.signatureHeader ?? 'x-hub-signature-256';
    const digestPrefix = config.digestPrefix ?? 'sha256=';
    const headerValue = readHeaderTrimmed(rawHeaders, signatureHeaderName);
    if (headerValue === undefined)
        return fail('missing_signature');
    if (!headerValue.startsWith(digestPrefix)) {
        // Present but structurally wrong — a malformed/forged value, not an
        // absent one.
        return fail('bad_signature');
    }
    const providedHex = headerValue.slice(digestPrefix.length);
    if (!HEX_CHARS_EVEN_LENGTH.test(providedHex)) {
        return fail('bad_signature');
    }
    if (rawBody === undefined)
        return fail('missing_body');
    const bodyBuffer = toBuffer(rawBody);
    // 3. Verify the signature (fail -> bad_signature). The explicit length
    //    pre-check runs BEFORE timingSafeEqual so a mismatched-length digest
    //    is rejected deterministically rather than by relying on
    //    timingSafeEqual's own throw-on-mismatch behavior.
    const computed = (0, node_crypto_1.createHmac)('sha256', secret).update(bodyBuffer).digest();
    const provided = Buffer.from(providedHex, 'hex');
    if (computed.length !== provided.length) {
        return fail('bad_signature');
    }
    if (!(0, node_crypto_1.timingSafeEqual)(computed, provided)) {
        return fail('bad_signature');
    }
    // No timestamp handling for this scheme (C2): GitHub-style HMAC signs only
    // the body, so there is no authenticated timestamp to validate.
    // 4. Replay protection — reached ONLY after a verified signature (C4).
    if (config.replay) {
        const defaultReplayId = (0, signRequest_1.sha256Hex)(providedHex.toLowerCase());
        const replayOutcome = await consumeReplay(config.replay, headers, rawBody, defaultReplayId);
        if (replayOutcome)
            return replayOutcome;
    }
    return OK;
}
// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------
const ED25519_PUBLIC_KEY_HEX = /^[0-9a-fA-F]{64}$/;
const ED25519_SIGNATURE_HEX = /^[0-9a-fA-F]{128}$/;
// DER SPKI prefix for a raw 32-byte ed25519 public key.
const ED25519_SPKI_PREFIX_HEX = '302a300506032b6570032100';
const STRICT_DECIMAL_INTEGER = /^[0-9]+$/;
async function resolveEd25519PublicKeyHex(config, headers) {
    try {
        const value = typeof config.publicKey === 'function' ? await config.publicKey(headers) : config.publicKey;
        return value && value.length > 0 ? value : undefined;
    }
    catch {
        return undefined;
    }
}
/** Strict decimal-integer parse: rejects non-finite/fractional/signed/trailing-char/whitespace input. */
function parseStrictSecondsTimestamp(raw) {
    if (!STRICT_DECIMAL_INTEGER.test(raw))
        return null;
    const value = Number(raw);
    return Number.isFinite(value) ? value : null;
}
async function verifyEd25519(config, rawBody, rawHeaders) {
    const headers = buildHeaderReader(rawHeaders);
    // 1. Resolve credential FIRST (C4).
    const publicKeyHex = await resolveEd25519PublicKeyHex(config, headers);
    if (publicKeyHex === undefined)
        return fail('missing_public_key');
    if (!ED25519_PUBLIC_KEY_HEX.test(publicKeyHex)) {
        // An invalid CONFIGURED key is a config error, never a per-request
        // forgery signal (C5).
        return fail('missing_public_key');
    }
    // 2. Read + strictly validate the signed inputs: signature header,
    //    timestamp header (raw bytes, preserved exactly — C5), body.
    const signatureHeaderName = config.signatureHeader ?? 'x-signature-ed25519';
    const signatureHex = readHeaderTrimmed(rawHeaders, signatureHeaderName);
    if (signatureHex === undefined)
        return fail('missing_signature');
    if (!ED25519_SIGNATURE_HEX.test(signatureHex)) {
        // Present but structurally wrong — malformed/forged, not absent.
        return fail('bad_signature');
    }
    const rawTimestamp = readHeaderRaw(rawHeaders, config.timestamp.header);
    if (rawTimestamp === undefined)
        return fail('missing_timestamp');
    if (rawBody === undefined)
        return fail('missing_body');
    const bodyBuffer = toBuffer(rawBody);
    // 3. Verify the signature (fail -> bad_signature; a resolver/crypto/config
    //    EXCEPTION during key construction or verification is NOT bad_signature
    //    — it means the configured key material is unusable, so it surfaces as
    //    missing_public_key rather than mislabeling a config problem as forgery).
    const message = Buffer.concat([Buffer.from(rawTimestamp, 'utf8'), bodyBuffer]);
    const signatureBuffer = Buffer.from(signatureHex, 'hex');
    let verified;
    try {
        const der = Buffer.concat([
            Buffer.from(ED25519_SPKI_PREFIX_HEX, 'hex'),
            Buffer.from(publicKeyHex, 'hex'),
        ]);
        const keyObject = (0, node_crypto_1.createPublicKey)({ key: der, format: 'der', type: 'spki' });
        verified = (0, node_crypto_1.verify)(null, message, keyObject, signatureBuffer);
    }
    catch {
        return fail('missing_public_key');
    }
    if (!verified)
        return fail('bad_signature');
    // 4. Parse + enforce the AUTHENTICATED timestamp skew (only now that the
    //    signature — which covers this exact header string — has verified).
    const parsedSeconds = parseStrictSecondsTimestamp(rawTimestamp);
    if (parsedSeconds === null)
        return fail('invalid_timestamp');
    const nowMs = config.timestamp.now ? config.timestamp.now() : Date.now();
    const skewSeconds = Math.abs(nowMs / 1000 - parsedSeconds);
    if (skewSeconds > config.timestamp.maxSkewSeconds)
        return fail('stale_timestamp');
    // 5. Replay protection — reached ONLY after a verified signature (C4).
    if (config.replay) {
        const defaultReplayId = (0, signRequest_1.sha256Hex)(signatureHex.toLowerCase());
        const replayOutcome = await consumeReplay(config.replay, headers, rawBody, defaultReplayId);
        if (replayOutcome)
            return replayOutcome;
    }
    return OK;
}
// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
/**
 * Verify an inbound webhook request's signature, returning a discriminated
 * outcome WITHOUT sending HTTP. Async because credential resolvers and
 * {@link NonceStore.consume} are async (C9).
 *
 * Ordering (C4) guarantees an unauthenticated request never reaches the
 * nonce store: resolve credential -> read/validate signature + signed inputs
 * -> verify signature -> (ed25519) enforce authenticated timestamp skew ->
 * derive authenticated replay id -> consume -> ok.
 */
function verifyWebhookSignature(input) {
    const { rawBody, headers, config } = input;
    if (config.scheme === 'hmac-sha256') {
        return verifyHmacSha256(config, rawBody, headers);
    }
    return verifyEd25519(config, rawBody, headers);
}
