import type { Request, RequestHandler } from 'express';
import { KeyGeneratorCore } from '../../core/rate-limit/keyGenerator';
import { RateLimitAlgorithm, RateLimiterLogger, RateLimitOverride, RateLimitRejectionCore, RateLimiterConfigCore } from '../../core/rate-limit/limiter';
/** Express-pinned alias: same shape as the pre-carve `KeyGenerator`. */
export type KeyGenerator = KeyGeneratorCore<Request>;
export type { RateLimitAlgorithm, RateLimiterLogger, RateLimitOverride };
/** Context passed to a custom `buildResponseBody` formatter on a 429. */
export type RateLimitRejection = RateLimitRejectionCore<Request>;
export type RateLimiterConfig = RateLimiterConfigCore<Request>;
/**
 * Create an Express rate-limit middleware.
 *
 * Pass a single config, or an ARRAY of tier configs applied in sequence — the
 * first tier to exceed its limit rejects the request (this is what enables the
 * recommended layered pattern: a coarse per-IP flood tier + a per-principal
 * fair-share tier). Each tier is independent; give tiers distinct stores/keys.
 */
export declare function createRateLimiter(config: RateLimiterConfig | RateLimiterConfig[]): RequestHandler;
