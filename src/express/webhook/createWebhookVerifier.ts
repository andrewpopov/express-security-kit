import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { verifyWebhookSignature } from '../../core/webhook/verify';
import type {
  WebhookHeaders,
  WebhookVerifyConfig,
  WebhookVerifyReason,
} from '../../core/webhook/verify';

/** Minimal logger surface; defaults to console. */
export interface WebhookVerifierLogger {
  warn: (message: string, meta?: unknown) => void;
}

/**
 * Express-only additions layered on top of the framework-agnostic
 * {@link WebhookVerifyConfig} (HMAC-SHA256 or ed25519 — see `core/webhook/verify.ts`).
 */
export interface WebhookVerifierExpressConfig {
  /**
   * Extract the raw (unparsed) request body bytes to verify the signature
   * against. Defaults to reading `req.rawBody`.
   *
   * REQUIRES upstream raw-body capture — typically
   * `express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } })`
   * mounted before this middleware. Without that hook `req.rawBody` is
   * `undefined` and every request fails closed with `missing_body` (401):
   * express's body parsers discard the original bytes once parsed, so there
   * is no other reliable source for the exact bytes the sender signed.
   */
  rawBody?: (req: Request) => string | Buffer | undefined;
  /**
   * Audit hook invoked on EVERY verification failure with the specific
   * machine-readable reason. The HTTP response stays generic; the reason is
   * for your logs only. Never affects the auth decision: a throwing hook or a
   * rejected returned promise is caught/logged (never awaited) and does not
   * change the response or crash the request. MUST NOT send a response; the
   * middleware owns the 401/503.
   */
  onFailure?: (
    req: Request,
    reason: WebhookVerifyReason,
  ) => void | Promise<unknown>;
  /** Logger for onFailure hook rejections/throws. Default: console. */
  logger?: WebhookVerifierLogger;
}

/**
 * Config for {@link createWebhookVerifier}: the core `WebhookVerifyConfig`
 * discriminated union (`scheme: 'hmac-sha256' | 'ed25519'`) plus the express
 * bits above.
 */
export type WebhookVerifierConfig = WebhookVerifyConfig & WebhookVerifierExpressConfig;

const consoleLogger: WebhookVerifierLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

/**
 * Reasons that mean "we can't currently make a decision" (missing/invalid
 * configured credential, or a nonce-store/resolver outage) → 503. Every other
 * reason means "this specific request failed verification" → 401. Matches the
 * design doc's C3 status mapping.
 */
const SERVICE_UNAVAILABLE_REASONS: ReadonlySet<WebhookVerifyReason> = new Set([
  'missing_secret',
  'missing_public_key',
  'store_unavailable',
]);

function statusForReason(reason: WebhookVerifyReason): 401 | 503 {
  return SERVICE_UNAVAILABLE_REASONS.has(reason) ? 503 : 401;
}

/** Send a generic 401. The specific reason is NEVER leaked to the client. */
function unauthorized(res: Response): void {
  res.status(401).json({
    error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
  });
}

/** Send a generic 503. The specific reason is NEVER leaked to the client. */
function serviceUnavailable(res: Response): void {
  res.status(503).json({
    error: { code: 'SERVICE_UNAVAILABLE', message: 'Service unavailable' },
  });
}

function defaultRawBody(req: Request): string | Buffer | undefined {
  return req.rawBody;
}

/**
 * Build an inbound-webhook signature verification middleware, wrapping the
 * framework-agnostic {@link verifyWebhookSignature}.
 *
 * FAILS CLOSED: any verification failure — or an unexpected throw anywhere in
 * this middleware — yields a GENERIC response and the request does NOT
 * proceed. The specific {@link WebhookVerifyReason} is passed ONLY to
 * `onFailure`, never to the client, so the response never leaks whether a
 * secret/key exists or which check failed.
 */
export function createWebhookVerifier(config: WebhookVerifierConfig): RequestHandler {
  const logger = config.logger ?? consoleLogger;
  const getRawBody = config.rawBody ?? defaultRawBody;

  const fail = (
    req: Request,
    res: Response,
    reason: WebhookVerifyReason,
    status: 401 | 503,
  ): void => {
    // An audit hook must never affect the decision, throw out, or leak an
    // unhandled rejection. Swallow sync throws and attach a .catch to promises.
    if (config.onFailure) {
      try {
        const maybePromise = config.onFailure(req, reason) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as Promise<unknown>).then === 'function'
        ) {
          (maybePromise as Promise<unknown>).catch((err) =>
            logger.warn('[express-security-kit] webhook onFailure hook rejected', err),
          );
        }
      } catch (err) {
        logger.warn('[express-security-kit] webhook onFailure hook threw', err);
      }
    }
    if (status === 503) serviceUnavailable(res);
    else unauthorized(res);
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawBody = getRawBody(req);
      const headers: WebhookHeaders = req.headers;
      const outcome = await verifyWebhookSignature({ rawBody, headers, config });
      if (outcome.ok) {
        return next();
      }
      return fail(req, res, outcome.reason, statusForReason(outcome.reason));
    } catch (err) {
      // FAIL CLOSED on any unexpected error (e.g. a throwing `rawBody`
      // extractor). Treated as a config/resolver-class failure (C3) — 503,
      // reported to onFailure as `store_unavailable`, the closest existing
      // "system trouble, not a per-request forgery" reason in the union.
      logger.warn('[express-security-kit] webhook verifier error', err);
      return fail(req, res, 'store_unavailable', 503);
    }
  };
}
