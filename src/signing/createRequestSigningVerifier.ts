import { createHmac } from 'node:crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { SecurityContext } from '../types';
import { timingSafeEqualHex } from '../api-key/hashers';
import { buildCanonicalString } from './signRequest';
import type { NonceStore } from './nonceStore';

/** Machine-readable failure reasons (passed to onFailure, never to the client). */
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

export interface SigningHeaderNames {
  timestamp: string;
  nonce: string;
  signature: string;
}

export type SecretResolver = (
  req: Request,
  ctx: SecurityContext | undefined,
) => string | undefined | Promise<string | undefined>;

export interface RequestSigningVerifierConfig {
  /**
   * Static shared secret, or a resolver. The resolver typically returns the
   * per-key secret from `ctx.hmacSecret` (populated by the api-key verifier),
   * or undefined when no secret is available → FAIL CLOSED.
   */
  secret: string | SecretResolver;
  /** Max clock skew in seconds. Default 300; clamped to [30, 900]. */
  maxSkewSeconds?: number;
  /** Header names. Defaults: x-timestamp / x-nonce / x-signature. */
  headerNames?: Partial<SigningHeaderNames>;
  /** Nonce format. Default /^[A-Za-z0-9:_-]{8,128}$/. */
  nonceFormat?: RegExp;
  /** Replay-protection store (required). */
  nonceStore: NonceStore;
  /**
   * Replay scope key. Default: `ctx.keyId ?? ctx.principalId ?? 'global'`.
   * Keeps one key's nonces from colliding with another's.
   */
  nonceScope?: (req: Request, ctx: SecurityContext | undefined) => string;
  /** Body-string extractor. Default: rawBody-first (see module docs). */
  bodySource?: (req: Request) => string;
  /**
   * When true, FAIL CLOSED (reason `'no_raw_body'`) for body-bearing methods
   * (never GET/HEAD, which have no body) if `req.rawBody` is absent — instead
   * of silently falling back to `JSON.stringify(req.body)`, which can produce
   * bytes that differ from what the client actually signed (see the module
   * docs' rawBody warning). Only governs the DEFAULT body extractor; a custom
   * `bodySource` participates as provided and is not affected. Default false.
   */
  requireRawBody?: boolean;
  /** Audit hook; receives the specific reason. May be async. MUST NOT respond. */
  onFailure?: (
    req: Request,
    reason: SigningFailureReason,
  ) => void | Promise<unknown>;
  /** Injectable clock (ms). Default Date.now. */
  now?: () => number;
  /** Logger for hook rejections / store errors. Default console. */
  logger?: SigningLogger;
}

const DEFAULT_NONCE_FORMAT = /^[A-Za-z0-9:_-]{8,128}$/;
const HEX_64 = /^[a-f0-9]{64}$/i;
const SKEW_MIN_SECONDS = 30;
const SKEW_MAX_SECONDS = 900;
const DEFAULT_SKEW_SECONDS = 300;

const consoleLogger: SigningLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

function clampSkewSeconds(value: number | undefined): number {
  const v = value ?? DEFAULT_SKEW_SECONDS;
  if (!Number.isFinite(v)) return DEFAULT_SKEW_SECONDS;
  return Math.min(SKEW_MAX_SECONDS, Math.max(SKEW_MIN_SECONDS, v));
}

/** First string value of a (possibly array) header. */
function headerValue(req: Request, name: string): string | undefined {
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
function defaultBodySource(req: Request): string {
  const method = (req.method ?? '').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return '';

  const rawBody = req.rawBody;
  if (typeof rawBody === 'string') return rawBody;
  if (Buffer.isBuffer(rawBody)) return rawBody.toString('utf8');

  const body = (req as { body?: unknown }).body;
  if (body === undefined || body === null) return '';
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  return JSON.stringify(body);
}

function defaultNonceScope(
  _req: Request,
  ctx: SecurityContext | undefined,
): string {
  return ctx?.keyId ?? ctx?.principalId ?? 'global';
}

function unauthorized(res: Response): void {
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
export function createRequestSigningVerifier(
  config: RequestSigningVerifierConfig,
): RequestHandler {
  const maxSkewSeconds = clampSkewSeconds(config.maxSkewSeconds);
  const maxSkewMs = maxSkewSeconds * 1000;
  const nonceFormat = config.nonceFormat ?? DEFAULT_NONCE_FORMAT;
  const headerNames: SigningHeaderNames = {
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

  const fail = (
    req: Request,
    res: Response,
    reason: SigningFailureReason,
  ): void => {
    if (config.onFailure) {
      try {
        const maybePromise = config.onFailure(req, reason) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as Promise<unknown>).then === 'function'
        ) {
          (maybePromise as Promise<unknown>).catch((err) =>
            logger.warn('[express-security-kit] signing onFailure rejected', err),
          );
        }
      } catch (err) {
        logger.warn('[express-security-kit] signing onFailure threw', err);
      }
    }
    unauthorized(res);
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const ctx = req.securityContext;

      // 1. Resolve the secret. Unresolved (undefined/empty) → fail closed.
      const secret =
        typeof config.secret === 'function'
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
      const canonical = buildCanonicalString({
        method: req.method,
        url: req.originalUrl,
        timestampMs,
        nonce,
        body: bodySource(req),
      });
      const expected = createHmac('sha256', secret)
        .update(canonical)
        .digest('hex');
      if (!timingSafeEqualHex(presented, expected)) {
        return fail(req, res, 'signature');
      }

      // 6. Replay protection: consume the nonce ONLY now that the signature is
      //    proven valid. Store unavailable (throw) → FAIL CLOSED.
      const scope = nonceScope(req, ctx);
      // Typed as unknown on purpose: a custom store might violate the contract
      // and return something other than 'ok' | 'replay'; we defend against that.
      let consumeResult: unknown;
      try {
        consumeResult = await config.nonceStore.consume(scope, nonce, maxSkewMs);
      } catch (err) {
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
        logger.warn(
          '[express-security-kit] nonce store returned an unexpected result',
          { result: consumeResult },
        );
        return fail(req, res, 'store_error');
      }

      return next();
    } catch (err) {
      // FAIL CLOSED on any unexpected error.
      logger.warn('[express-security-kit] signing verifier error', err);
      return fail(req, res, 'error');
    }
  };
}
