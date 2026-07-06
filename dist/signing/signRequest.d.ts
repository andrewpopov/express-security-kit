export interface CanonicalStringInput {
    /** HTTP method (case-insensitive; upper-cased in the canonical string). */
    method: string;
    /** Request target exactly as received (path + query), e.g. req.originalUrl. */
    url: string;
    /** Millisecond epoch timestamp. */
    timestampMs: number;
    /** Per-request nonce. */
    nonce: string;
    /** Request body. Ignored for GET/HEAD (hashed as ''). */
    body?: string;
}
/** sha256 hex of a string (utf8). Exported so callers can hash bodies too. */
export declare function sha256Hex(input: string): string;
/**
 * Build the canonical string that gets HMAC-signed. Five LF-joined lines:
 *
 *   METHOD (upper) \n url \n String(timestampMs) \n nonce \n sha256hex(body)
 *
 * For GET/HEAD the body is treated as '' → sha256hex(''). This reproduces
 * stoki's scheme byte-for-byte.
 */
export declare function buildCanonicalString(input: CanonicalStringInput): string;
export interface SignRequestInput extends CanonicalStringInput {
    /** Shared HMAC secret (per-key or global). */
    secret: string;
}
export interface SignedRequest {
    /** Lowercase 64-char hex HMAC-SHA256 signature. */
    signature: string;
    /** Headers a client must send alongside the request. */
    headers: {
        'X-Timestamp': string;
        'X-Nonce': string;
        'X-Signature': string;
    };
}
/**
 * Compute a signature compatible with {@link createRequestSigningVerifier} (and
 * with stoki's live scheme). Client/service-side helper.
 */
export declare function signRequest(input: SignRequestInput): SignedRequest;
