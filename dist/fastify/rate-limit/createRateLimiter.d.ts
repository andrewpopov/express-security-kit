import type { FastifyReply, FastifyRequest } from 'fastify';
import { KeyGeneratorCore } from '../../core/rate-limit/keyGenerator';
import { RateLimiterConfigCore, RateLimitRejectionCore } from '../../core/rate-limit/limiter';
/** Fastify-pinned alias: same shape as the Express `KeyGenerator`. */
export type FastifyKeyGenerator = KeyGeneratorCore<FastifyRequest>;
/** Context passed to a custom `buildResponseBody` formatter on a 429. */
export type FastifyRateLimitRejection = RateLimitRejectionCore<FastifyRequest>;
export type FastifyRateLimiterConfig = RateLimiterConfigCore<FastifyRequest>;
/**
 * Create a Fastify rate-limit `preHandler`.
 *
 * Pass a single config, or an ARRAY of tier configs applied in sequence — the
 * first tier to exceed its limit rejects the request (this is what enables the
 * recommended layered pattern: a coarse per-IP flood tier + a per-principal
 * fair-share tier). Each tier is independent; give tiers distinct stores/keys.
 *
 * This is deliberately mounted as a **`preHandler`**, not an `onRequest` hook
 * — the same lifecycle stage the Fastify api-key adapter uses. `hmacBodyFieldKey`
 * keys on a request-body field, and in Fastify the body is only parsed by the
 * time `preHandler` runs; an `onRequest` limiter would silently fall back to
 * IP keying for that strategy.
 *
 * No decision logic lives here — every number, header value, and body comes
 * from {@link createRateLimitCore}. This function only translates a
 * `RateLimitOutcome` into `reply` calls: it sets headers, sends the 429, and
 * (for `skipSuccessful`) hooks `reply.raw` via {@link scheduleRefundOnFinish}.
 * A tier that rejects `await reply.code(...).send(...)`s and returns straight
 * out of the loop — awaiting the send inside the `preHandler`'s promise chain
 * halts the lifecycle, so the route handler is never reached, the same
 * mechanism the api-key adapter relies on. There is no need to consult
 * `reply.sent` the way the Express adapter checks `res.headersSent`: the
 * Express adapter dispatches tiers through `next()` callbacks and has no other
 * way to know a tier already responded, but here the loop is owned directly.
 *
 * The DECISION and the BOOK-KEEPING fail OPEN: a tier that cannot reach a
 * decision (an unexpected throw from `evaluate()`, which already fails open
 * internally) is skipped, and a throwing header/refund-hook call on the ALLOW
 * path is logged via the same `safeWarn` path the core and Express adapter
 * use, with the request proceeding to the route handler. Once a tier has
 * DECIDED to reject, that is no longer true: writing the rejection (headers +
 * the 429 send) is NOT wrapped in a fail-open catch, so a failure there
 * propagates to Fastify's error handler (a 500) instead of silently letting
 * an over-limit request reach the route. A rate limiter must never take the
 * service down, but failing to WRITE a rejection must never become
 * permission to RUN the route either.
 */
export declare function createRateLimiter(config: FastifyRateLimiterConfig | FastifyRateLimiterConfig[]): (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
