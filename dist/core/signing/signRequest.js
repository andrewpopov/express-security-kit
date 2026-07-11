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
const CRLF = /[\r\n]/;
/**
 * Reject a raw CR/LF in a field that gets embedded directly (unhashed) into
 * the LF-joined canonical string. `method`/`url`/`nonce` are embedded as-is;
 * `timestampMs` is numeric (can't carry CR/LF) and `body` is hashed (its
 * sha256 output can't carry CR/LF either), so only these three need the
 * guard. Without it, a `url`/`nonce` (or forged `method`) containing `\n`
 * could make two DISTINCT input tuples canonicalize to the SAME 5-line
 * string (line-count ambiguity), which would let a signature be replayed
 * against a different request. Valid HTTP requests never carry a raw CR/LF
 * in these fields, so this only rejects malformed/hostile input — the wire
 * format for valid inputs is unchanged (stoki compat preserved).
 */
function assertNoCrlf(field, value) {
    if (CRLF.test(value)) {
        throw new Error(`Invalid canonical field: ${field} must not contain CR/LF`);
    }
}
/**
 * Build the canonical string that gets HMAC-signed. Five LF-joined lines:
 *
 *   METHOD (upper) \n url \n String(timestampMs) \n nonce \n sha256hex(body)
 *
 * For GET/HEAD the body is treated as '' → sha256hex(''). This reproduces
 * stoki's scheme byte-for-byte.
 *
 * Throws if `method`, `url`, or `nonce` contains a raw CR or LF (see {@link
 * assertNoCrlf}).
 */
function buildCanonicalString(input) {
    const { method, url, timestampMs, nonce } = input;
    assertNoCrlf('method', method);
    assertNoCrlf('url', url);
    assertNoCrlf('nonce', nonce);
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
