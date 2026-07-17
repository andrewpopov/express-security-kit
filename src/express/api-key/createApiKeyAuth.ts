import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { verifyApiKey } from '../../core/api-key/verifyApiKey';
import type {
  ApiKeyAuthConfigCore,
  ApiKeyAuthLogger,
  ApiKeyErrorResponse,
  ApiKeyFailureReason,
} from '../../core/api-key/types';

/** Express-pinned config: same shape as the pre-carve `ApiKeyAuthConfig`. */
export type ApiKeyAuthConfig = ApiKeyAuthConfigCore<Request>;

const consoleLogger: ApiKeyAuthLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

/** Send a generic 401. The specific reason is NEVER leaked to the client. */
function unauthorized(res: Response): void {
  res.status(401).json({
    error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
  });
}

/** Send a generic 403. */
function forbidden(res: Response): void {
  res.status(403).json({
    error: { code: 'FORBIDDEN', message: 'Forbidden' },
  });
}

/** Default body for an `'error'` (infrastructure-failure) response. */
function defaultErrorBody(status: number): unknown {
  return status === 503
    ? { error: { code: 'SERVICE_UNAVAILABLE', message: 'Service Unavailable' } }
    : { error: { code: 'INTERNAL_ERROR', message: 'Internal Server Error' } };
}

/**
 * Build an API-key authentication middleware.
 *
 * Auth FAILS CLOSED: any failure (missing/bad/expired/denied key, or an
 * unexpected error such as a throwing `lookup`/`hasher`) yields a GENERIC
 * response and the request does NOT proceed. This is the opposite of the
 * rate limiter, which fails open. Only the `onFailure` audit hook receives
 * the specific reason.
 *
 * A `reason: 'error'` or `reason: 'unavailable'` outcome (the check could not
 * be performed — e.g. a DB outage, or a `rawAuthenticator` reporting its
 * backing infrastructure is unavailable) is DELIBERATELY distinct from an
 * auth failure: it responds with `config.errorStatus` (default **503**, not
 * 401) — see `ApiKeyAuthConfig`. A DB outage reported as 401 makes monitoring
 * blind to the outage and causes clients to treat valid keys as revoked and
 * re-provision.
 *
 * This is a thin middleware wrapper around {@link verifyApiKey}: it applies the
 * `optional`-passthrough policy and translates the verification outcome into an
 * HTTP response; the verification core lives in verifyApiKey.
 */
export function createApiKeyAuth(config: ApiKeyAuthConfig): RequestHandler {
  const logger = config.logger ?? consoleLogger;

  const fail = async (
    req: Request,
    res: Response,
    reason: ApiKeyFailureReason,
    status: number,
  ): Promise<void> => {
    // An audit hook must never affect the auth decision, throw out, or leak an
    // unhandled rejection. Swallow sync throws and attach a .catch to promises.
    if (config.onFailure) {
      try {
        const maybePromise = config.onFailure(req, reason) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as Promise<unknown>).then === 'function'
        ) {
          (maybePromise as Promise<unknown>).catch((err) =>
            logger.warn('[express-security-kit] onFailure hook rejected', err),
          );
        }
      } catch (err) {
        logger.warn('[express-security-kit] onFailure hook threw', err);
      }
    }

    if (reason === 'error' || reason === 'unavailable') {
      // Infrastructure failure (internal 'error', or a rawAuthenticator
      // reporting 'unavailable' — e.g. an unloaded pepper ring): `status`
      // here is already `errorStatus` (resolved by verifyApiKey). `onError`
      // may further customize the status/body; a throw/rejection from it
      // falls back to the default — it can never turn this into an allow or
      // leave the response unsent.
      let response: ApiKeyErrorResponse = { status };
      if (config.onError) {
        try {
          const custom = await config.onError(req);
          if (custom) response = custom;
        } catch (err) {
          logger.warn('[express-security-kit] onError hook threw', err);
        }
      }
      res.status(response.status).json(response.body ?? defaultErrorBody(response.status));
      return;
    }

    if (status === 403) forbidden(res);
    else unauthorized(res);
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    const outcome = await verifyApiKey(config, req);
    if (outcome.ok) {
      req.securityContext = outcome.context;
      return next();
    }
    // In optional mode, pass through ONLY a genuinely absent credential; a
    // present-but-invalid credential is a failed auth attempt and is rejected
    // even when optional.
    if (!outcome.present && config.optional) {
      return next();
    }
    return await fail(req, res, outcome.reason, outcome.status);
  };
}
