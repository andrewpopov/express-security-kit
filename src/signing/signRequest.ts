import { createHash, createHmac } from 'node:crypto';

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
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function isBodylessMethod(method: string): boolean {
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
export function buildCanonicalString(input: CanonicalStringInput): string {
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
export function signRequest(input: SignRequestInput): SignedRequest {
  const canonical = buildCanonicalString(input);
  const signature = createHmac('sha256', input.secret)
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
