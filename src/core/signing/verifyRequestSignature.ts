import { createHmac } from 'node:crypto';
import { timingSafeEqualHex } from '../api-key/hashers';
import { buildCanonicalString } from './signRequest';
import type { NonceStore } from './nonceStore';

/**
 * Machine-readable failure reasons for request-signature verification (an
 * adapter passes these to its own `onFailure`/audit hook — NEVER to the
 * client). This is decision vocabulary, not an HTTP concern, so it lives here
 * rather than in any one adapter; the Express adapter re-exports it so
 * existing imports keep working.
 */
export type SigningFailureReason =
  | 'no_secret'
  | 'timestamp'
  | 'skew'
  | 'nonce'
  | 'signature'
  | 'replay'
  | 'store_error'
  | 'no_raw_body'
  | 'error';

/** Minimal logger surface; defaults to console. */
export interface SigningLogger {
  warn: (message: string, meta?: unknown) => void;
}

const consoleLogger: SigningLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

const DEFAULT_NONCE_FORMAT = /^[A-Za-z0-9:_-]{8,128}$/;
const HEX_64 = /^[a-f0-9]{64}$/i;
const SKEW_MIN_SECONDS = 30;
const SKEW_MAX_SECONDS = 900;
const DEFAULT_SKEW_SECONDS = 300;

function clampSkewSeconds(value: number | undefined): number {
  const v = value ?? DEFAULT_SKEW_SECONDS;
  if (!Number.isFinite(v)) return DEFAULT_SKEW_SECONDS;
  return Math.min(SKEW_MAX_SECONDS, Math.max(SKEW_MIN_SECONDS, v));
}

export interface RequestSignatureVerifierConfigCore {
  /** Max clock skew in seconds. Default 300; clamped to [30, 900]. */
  maxSkewSeconds?: number;
  /** Nonce format. Default /^[A-Za-z0-9:_-]{8,128}$/. */
  nonceFormat?: RegExp;
  /** Replay-protection store (required). */
  nonceStore: NonceStore;
  /**
   * When true, FAIL CLOSED (reason `'no_raw_body'`) whenever the caller
   * reports `input.hasRawBody: false`. What "has raw body" means for a given
   * request — the bodyless GET/HEAD exemption, whether a custom body
   * extractor is in play — is entirely the CALLER's job to resolve before
   * calling `verify`; the core only enforces the policy against whatever the
   * caller reports. Default false.
   */
  requireRawBody?: boolean;
  /** Injectable clock (ms). Default Date.now. */
  now?: () => number;
  /** Logger for store errors / unexpected failures. Default console. */
  logger?: SigningLogger;
}

/**
 * Plain facts the core needs to verify one request's signature. Every
 * framework-specific extraction — reading headers, resolving the body
 * source, resolving the secret, deriving the nonce scope — is the CALLER's
 * job; this carries only already-resolved values, never a framework request
 * object.
 */
export interface RequestSignatureVerifyInput {
  /** HTTP method (case-insensitive; upper-cased for the canonical string). */
  method: string;
  /** Request target exactly as received (path + query), e.g. req.originalUrl. */
  url: string;
  /** Raw timestamp header value, if present. */
  timestampHeader: string | undefined;
  /** Raw nonce header value, if present. */
  nonceHeader: string | undefined;
  /** Raw signature header value, if present. */
  signatureHeader: string | undefined;
  /** Exact bytes to hash into the canonical string. Ignored for GET/HEAD. */
  body: string;
  /**
   * Resolved HMAC secret (per-key or global). Undefined/empty → fail closed
   * (`no_secret`).
   */
  secret: string | undefined;
  /**
   * Replay-protection scope key, so one principal's nonces never collide with
   * another's.
   */
  nonceScope: string;
  /**
   * Whether the `requireRawBody` precondition is satisfied for this request.
   * Only consulted when `config.requireRawBody` is true.
   */
  hasRawBody: boolean;
}

export type RequestSignatureVerifyOutcome =
  | { type: 'ok' }
  | { type: 'fail'; reason: SigningFailureReason };

export interface RequestSignatureVerifierCore {
  /** NEVER throws — any internal failure fails CLOSED as a `fail` outcome. */
  verify(input: RequestSignatureVerifyInput): Promise<RequestSignatureVerifyOutcome>;
}

/** Log a warning without ever letting a throwing logger break verification. */
function safeWarn(
  config: RequestSignatureVerifierConfigCore,
  message: string,
  err: unknown,
): void {
  try {
    (config.logger ?? consoleLogger).warn(message, err);
  } catch {
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
export function createRequestSignatureVerifierCore(
  config: RequestSignatureVerifierConfigCore,
): RequestSignatureVerifierCore {
  const maxSkewSeconds = clampSkewSeconds(config.maxSkewSeconds);
  const maxSkewMs = maxSkewSeconds * 1000;
  const nonceFormat = config.nonceFormat ?? DEFAULT_NONCE_FORMAT;
  const requireRawBody = config.requireRawBody ?? false;
  const clock = config.now ?? Date.now;

  async function verify(
    input: RequestSignatureVerifyInput,
  ): Promise<RequestSignatureVerifyOutcome> {
    try {
      // 1. Secret must already be resolved. Unresolved (undefined/empty) →
      //    fail closed.
      if (!input.secret) {
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

      // 4b. requireRawBody: the caller has already resolved what "has raw
      //     body" means for THIS request (bodyless-method exemption, custom
      //     extractor passthrough); the core only enforces the policy.
      if (requireRawBody && !input.hasRawBody) {
        return { type: 'fail', reason: 'no_raw_body' };
      }

      // 5. Recompute the expected signature and timing-safe compare.
      const canonical = buildCanonicalString({
        method: input.method,
        url: input.url,
        timestampMs,
        nonce,
        body: input.body,
      });
      const expected = createHmac('sha256', input.secret).update(canonical).digest('hex');
      if (!timingSafeEqualHex(presented, expected)) {
        return { type: 'fail', reason: 'signature' };
      }

      // 6. Replay protection: consume the nonce ONLY now that the signature
      //    is proven valid. Store unavailable (throw) → FAIL CLOSED.
      // Typed as unknown on purpose: a custom store might violate the
      // contract and return something other than 'ok' | 'replay'; we defend
      // against that.
      let consumeResult: unknown;
      try {
        consumeResult = await config.nonceStore.consume(input.nonceScope, nonce, maxSkewMs);
      } catch (err) {
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
    } catch (err) {
      // FAIL CLOSED on any unexpected error.
      safeWarn(config, '[express-security-kit] signing verifier error', err);
      return { type: 'fail', reason: 'error' };
    }
  }

  return { verify };
}
