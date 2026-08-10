import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { SecurityContext } from '../../core/context';
import { createRequestSignatureVerifierCore } from '../../core/signing/verifyRequestSignature';
import type {
  RequestSignatureVerifyInput,
  SigningFailureReason,
  SigningLogger,
} from '../../core/signing/verifyRequestSignature';
import type { NonceStore } from '../../core/signing/nonceStore';

// `SigningFailureReason` / `SigningLogger` now live in the framework-agnostic
// core (PKG-151) — decision vocabulary, not an HTTP concern, shared by every
// adapter that calls `createRequestSignatureVerifierCore`. Re-exported here
// (and thus from the package root) so existing consumer imports of these two
// names from this module keep working unchanged.
export type { SigningFailureReason, SigningLogger };

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

const consoleLogger: SigningLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

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
 * This is a THIN adapter over {@link createRequestSignatureVerifierCore}: all
 * decision logic (ordering, fail-closed semantics, the nonce-consumed-after-
 * signature-proven rule) lives in the framework-agnostic core. This module
 * only does Express-specific extraction — reading headers, resolving the body
 * source, resolving the secret, deriving the nonce scope, and the
 * `requireRawBody` bodyless/custom-extractor exemption — and translates the
 * core's outcome into a response (`onFailure` + generic 401, or `next()`).
 */
export function createRequestSigningVerifier(
  config: RequestSigningVerifierConfig,
): RequestHandler {
  const headerNames: SigningHeaderNames = {
    timestamp: config.headerNames?.timestamp ?? 'x-timestamp',
    nonce: config.headerNames?.nonce ?? 'x-nonce',
    signature: config.headerNames?.signature ?? 'x-signature',
  };
  const nonceScope = config.nonceScope ?? defaultNonceScope;
  const usingDefaultBodySource = config.bodySource === undefined;
  const bodySource = config.bodySource ?? defaultBodySource;
  const logger = config.logger ?? consoleLogger;

  const core = createRequestSignatureVerifierCore({
    maxSkewSeconds: config.maxSkewSeconds,
    nonceFormat: config.nonceFormat,
    nonceStore: config.nonceStore,
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
  function hasRawBody(req: Request): boolean {
    if (!usingDefaultBodySource) return true;
    const method = (req.method ?? '').toUpperCase();
    if (method === 'GET' || method === 'HEAD') return true;
    const rawBody = req.rawBody;
    return typeof rawBody === 'string' || Buffer.isBuffer(rawBody);
  }

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

      // Resolve the secret. Unresolved (undefined/empty) → the core fails
      // closed with `no_secret`.
      const secret =
        typeof config.secret === 'function'
          ? await config.secret(req, ctx)
          : config.secret;

      const input: RequestSignatureVerifyInput = {
        method: req.method,
        url: req.originalUrl,
        timestampHeader: headerValue(req, headerNames.timestamp),
        nonceHeader: headerValue(req, headerNames.nonce),
        signatureHeader: headerValue(req, headerNames.signature),
        body: bodySource(req),
        secret,
        nonceScope: nonceScope(req, ctx),
        hasRawBody: hasRawBody(req),
      };

      const outcome = await core.verify(input);
      if (outcome.type === 'fail') {
        return fail(req, res, outcome.reason);
      }

      return next();
    } catch (err) {
      // FAIL CLOSED on any unexpected error (including a throwing secret
      // resolver, which the core never sees).
      logger.warn('[express-security-kit] signing verifier error', err);
      return fail(req, res, 'error');
    }
  };
}
