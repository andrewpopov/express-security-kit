"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256Hex = sha256Hex;
exports.buildCanonicalString = buildCanonicalString;
exports.signRequest = signRequest;
const node_crypto_1 = require("node:crypto");
/** sha256 hex of a string (utf8). Exported so callers can hash bodies too. */
function sha256Hex(input) {
    return (0, node_crypto_1.createHash)('sha256').update(input).digest('hex');
}
function isBodylessMethod(method) {
    const m = method.toUpperCase();
    return m === 'GET' || m === 'HEAD';
}
/**
 * Build the canonical string that gets HMAC-signed. Five LF-joined lines:
 *
 *   METHOD (upper) \n url \n String(timestampMs) \n nonce \n sha256hex(body)
 *
 * For GET/HEAD the body is treated as '' → sha256hex(''). This reproduces
 * stoki's scheme byte-for-byte.
 */
function buildCanonicalString(input) {
    const { method, url, timestampMs, nonce } = input;
    const bodyHash = isBodylessMethod(method)
        ? sha256Hex('')
        : sha256Hex(input.body ?? '');
    return [
        method.toUpperCase(),
        url,
        String(timestampMs),
        nonce,
        bodyHash,
    ].join('\n');
}
/**
 * Compute a signature compatible with {@link createRequestSigningVerifier} (and
 * with stoki's live scheme). Client/service-side helper.
 */
function signRequest(input) {
    const canonical = buildCanonicalString(input);
    const signature = (0, node_crypto_1.createHmac)('sha256', input.secret)
        .update(canonical)
        .digest('hex');
    return {
        signature,
        headers: {
            'X-Timestamp': String(input.timestampMs),
            'X-Nonce': input.nonce,
            'X-Signature': signature,
        },
    };
}
