import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { KeyGeneratorCore } from '../../core/rate-limit/keyGenerator';
import {
  createRateLimitCore,
  safeWarn,
  scheduleRefundOnFinish,
  RateLimitAlgorithm,
  RateLimiterLogger,
  RateLimitOverride,
  RateLimitRejectionCore,
  RateLimiterConfigCore,
} from '../../core/rate-limit/limiter';

/** Express-pinned alias: same shape as the pre-carve `KeyGenerator`. */
export type KeyGenerator = KeyGeneratorCore<Request>;

export type { RateLimitAlgorithm, RateLimiterLogger, RateLimitOverride };

/** Context passed to a custom `buildResponseBody` formatter on a 429. */
export type RateLimitRejection = RateLimitRejectionCore<Request>;

export type RateLimiterConfig = RateLimiterConfigCore<Request>;

function buildSingleLimiter(config: RateLimiterConfig): RequestHandler {
  const core = createRateLimitCore<Request>(config);
  // Unique per THIS limiter so tiered limiters each refund their own counted
  // hit (a per-response flag would let only the first tier refund).
  const refundFlag = Symbol('express-security-kit.rateLimitRefund');

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const outcome = await core.evaluate(req);

      if (outcome.type === 'skip') {
        return next();
      }

      for (const [name, value] of outcome.headers) {
        res.setHeader(name, value);
      }

      if (outcome.type === 'reject') {
        return res.status(outcome.status).json(outcome.body);
      }

      if (outcome.onSettled) {
        scheduleRefundOnFinish(res, outcome.onSettled, refundFlag, (err) =>
          safeWarn(config, '[express-security-kit] could not hook response for refund', err),
        );
      }
      return next();
    } catch (err) {
      // Any unexpected error also fails open (safeWarn so a throwing logger
      // can't prevent next()). `res.setHeader` can throw once headers are
      // sent, and the pre-carve code failed open there too.
      safeWarn(
        config,
        '[express-security-kit] rate-limit unexpected error; failing open',
        err,
      );
      return next();
    }
  };
}

/**
 * Create an Express rate-limit middleware.
 *
 * Pass a single config, or an ARRAY of tier configs applied in sequence — the
 * first tier to exceed its limit rejects the request (this is what enables the
 * recommended layered pattern: a coarse per-IP flood tier + a per-principal
 * fair-share tier). Each tier is independent; give tiers distinct stores/keys.
 */
export function createRateLimiter(
  config: RateLimiterConfig | RateLimiterConfig[],
): RequestHandler {
  if (Array.isArray(config)) {
    const tiers = config.map(buildSingleLimiter);
    return (req: Request, res: Response, next: NextFunction) => {
      let index = 0;
      const runNext = (err?: unknown): void => {
        if (err) return next(err);
        // A tier that rejected has already sent the 429 response.
        if (res.headersSent) return;
        const tier = tiers[index++];
        if (!tier) return next();
        tier(req, res, runNext as NextFunction);
      };
      runNext();
    };
  }
  return buildSingleLimiter(config);
}
