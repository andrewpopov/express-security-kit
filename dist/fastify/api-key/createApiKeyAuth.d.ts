import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ApiKeyAuthConfigCore } from '../../core/api-key/types';
/** Fastify-pinned config: same shape as the Express `ApiKeyAuthConfig`. */
export type FastifyApiKeyAuthConfig = ApiKeyAuthConfigCore<FastifyRequest>;
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
export declare function createApiKeyAuth(config: FastifyApiKeyAuthConfig): (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
