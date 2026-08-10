import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  verifyApiKey,
  describeApiKeyConfigError,
  warnIfBothCredentialPathsConfigured,
} from '../../core/api-key/verifyApiKey';
import type {
  ApiKeyAuthConfigCore,
  ApiKeyAuthLogger,
  ApiKeyErrorResponse,
  ApiKeyFailureReason,
} from '../../core/api-key/types';

/** Fastify-pinned config: same shape as the Express `ApiKeyAuthConfig`. */
export type FastifyApiKeyAuthConfig = ApiKeyAuthConfigCore<FastifyRequest>;

const consoleLogger: ApiKeyAuthLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

/** Send a generic 401. The specific reason is NEVER leaked to the client. */
async function unauthorized(reply: FastifyReply): Promise<void> {
  await reply.code(401).send({
    error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
  });
}

/** Send a generic 403. */
async function forbidden(reply: FastifyReply): Promise<void> {
  await reply.code(403).send({
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
 * Build an API-key authentication `preHandler` for Fastify.
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
 * 401) — see `ApiKeyAuthConfigCore`. A DB outage reported as 401 makes
 * monitoring blind to the outage and causes clients to treat valid keys as
 * revoked and re-provision.
 *
 * This is a thin `preHandler` wrapper around {@link verifyApiKey}: it applies
 * the `optional`-passthrough policy and translates the verification outcome
 * into an HTTP response; the verification core lives in verifyApiKey. Success
 * assigns `request.securityContext` and returns, letting Fastify continue to
 * the route handler; failure sends the reply directly — a Fastify
 * `preHandler` that sends a reply short-circuits the lifecycle, so the route
 * handler is never reached.
 *
 * @throws {Error} synchronously, at construction time (never per-request), if
 * `config` supplies NEITHER `rawAuthenticator` nor `lookup` — a programmer
 * error caught eagerly rather than surfacing as a 503 on every request. See
 * `ApiKeyAuthConfigCore.rawAuthenticator`. Supplying BOTH does not throw —
 * `rawAuthenticator` wins and a one-time deprecation warning is logged.
 */
export function createApiKeyAuth(
  config: FastifyApiKeyAuthConfig,
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  const configError = describeApiKeyConfigError(config);
  if (configError) {
    throw new Error(`createApiKeyAuth: ${configError}`);
  }
  warnIfBothCredentialPathsConfigured(config);
  const logger = config.logger ?? consoleLogger;

  const fail = async (
    request: FastifyRequest,
    reply: FastifyReply,
    reason: ApiKeyFailureReason,
    status: number,
  ): Promise<void> => {
    // An audit hook must never affect the auth decision, throw out, or leak an
    // unhandled rejection. Swallow sync throws and attach a .catch to promises.
    if (config.onFailure) {
      try {
        const maybePromise = config.onFailure(request, reason) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as Promise<unknown>).then === 'function'
        ) {
          (maybePromise as Promise<unknown>).catch((err) =>
            logger.warn('[express-security-kit/fastify] onFailure hook rejected', err),
          );
        }
      } catch (err) {
        logger.warn('[express-security-kit/fastify] onFailure hook threw', err);
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
          const custom = await config.onError(request);
          if (custom) response = custom;
        } catch (err) {
          logger.warn('[express-security-kit/fastify] onError hook threw', err);
        }
      }
      await reply
        .code(response.status)
        .send(response.body ?? defaultErrorBody(response.status));
      return;
    }

    if (status === 403) await forbidden(reply);
    else await unauthorized(reply);
  };

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const outcome = await verifyApiKey(config, request);
    if (outcome.ok) {
      request.securityContext = outcome.context;
      return;
    }
    // In optional mode, pass through ONLY a genuinely absent credential; a
    // present-but-invalid credential is a failed auth attempt and is rejected
    // even when optional.
    if (!outcome.present && config.optional) {
      return;
    }
    await fail(request, reply, outcome.reason, outcome.status);
  };
}
