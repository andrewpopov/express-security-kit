import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { MemoryRateLimitStore, RateLimitStore } from './store';
import {
  defaultKeyGenerator,
  KeyGenerator,
} from './keyGenerator';

export type RateLimitAlgorithm = 'fixed' | 'sliding';

/** Minimal logger surface; defaults to console. */
export interface RateLimiterLogger {
  warn: (message: string, meta?: unknown) => void;
}

export interface RateLimitOverride {
  windowMs: number;
  max: number;
}

/** Context passed to a custom `buildResponseBody` formatter on a 429. */
export interface RateLimitRejection {
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfterSeconds: number;
  key: string;
  req: Request;
}

export interface RateLimiterConfig {
  /** Window length in ms. */
  windowMs: number;
  /** Max requests per window. A function receives the request for role-aware limits. */
  max: number | ((req: Request) => number);
  /** 'fixed' (default) or 'sliding' window counter. */
  algorithm?: RateLimitAlgorithm;
  /** Key generator. Default: verifiedIdentityKey (aka defaultKeyGenerator). */
  keyGenerator?: KeyGenerator;
  /** Backing store. Default: a shared in-process MemoryRateLimitStore. */
  store?: RateLimitStore;
  /**
   * Resolve a per-request override. Default reads
   * `req.securityContext?.rateLimitOverride`. Return undefined for no override.
   */
  overrideResolver?: (req: Request) => RateLimitOverride | undefined;
  /** Skip limiting entirely for a request (e.g. health checks, dev mode). */
  skip?: (req: Request) => boolean;
  /**
   * Called when a request is rejected with 429. May be async. A throw or a
   * rejected promise is swallowed (logged) and NEVER prevents the 429.
   */
  onLimit?: (req: Request, key: string) => void | Promise<unknown>;
  /**
   * Override ONLY the message text inside the default 429 envelope. The default
   * body shape (`{ error: { code: 'RATE_LIMITED', message, retryAfter } }`) and
   * code are unchanged. Ignored when `buildResponseBody` is set.
   */
  message?: string;
  /**
   * Return the ENTIRE 429 JSON body, replacing the default envelope — so a
   * service can match its own API error shape. A throwing formatter can never
   * break the response: on throw the default body is sent and the error logged.
   * Takes precedence over `message`.
   */
  buildResponseBody?: (info: RateLimitRejection) => unknown;
  /**
   * When true, REFUND (decrement) the counted hit for a request that ends with
   * a status < 400, so only failed requests count toward the limit — mirrors
   * express-rate-limit's `skipSuccessfulRequests` (e.g. an auth limiter where
   * only failed logins should count). The refund fires once on response
   * `finish`/`close`. Default false. Requires a store that implements
   * `decrement` (the built-in Memory and Redis stores do).
   */
  skipSuccessful?: boolean;
  /** Emit RateLimit-* + Retry-After headers. Default true. */
  headers?: boolean;
  /** Logger for fail-open store errors. Default: console. */
  logger?: RateLimiterLogger;
  /** Injectable clock for deterministic tests. Default: Date.now. */
  now?: () => number;
}

const consoleLogger: RateLimiterLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

/**
 * A shared default store so multiple limiters created without an explicit
 * `store` don't each spin up their own bucket map + timer. Tiers that must not
 * share state should pass their own store.
 */
let sharedMemoryStore: MemoryRateLimitStore | undefined;
function getSharedStore(): MemoryRateLimitStore {
  if (!sharedMemoryStore) {
    sharedMemoryStore = new MemoryRateLimitStore();
  }
  return sharedMemoryStore;
}

interface ResolvedDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  /** Effective count used for the decision (weighted for sliding). */
  used: number;
}

function resolveMax(
  config: RateLimiterConfig,
  req: Request,
  override: RateLimitOverride | undefined,
): { windowMs: number; max: number } {
  if (override) {
    return { windowMs: override.windowMs, max: override.max };
  }
  const max = typeof config.max === 'function' ? config.max(req) : config.max;
  return { windowMs: config.windowMs, max };
}

/**
 * Apply the algorithm to a store hit to produce a decision.
 *
 * fixed:   reject when current > max (current already includes this hit).
 * sliding: weighted = previous * (1 - elapsedInCurrent/windowMs) + current;
 *          reject when weighted >= max.
 */
function decide(
  algorithm: RateLimitAlgorithm,
  hit: { current: number; previous: number; resetAt: number },
  windowMs: number,
  max: number,
  now: number,
): ResolvedDecision {
  if (algorithm === 'sliding') {
    const windowStart = hit.resetAt - windowMs;
    const elapsedInCurrent = Math.min(windowMs, Math.max(0, now - windowStart));
    const weightPrevious = Math.max(0, 1 - elapsedInCurrent / windowMs);
    const weighted = hit.previous * weightPrevious + hit.current;
    // `max` means the same thing across algorithms: allow up to and including
    // `max`, reject only when the weighted estimate EXCEEDS it. In an empty
    // window this lets exactly `max` through, matching the fixed window.
    const allowed = weighted <= max;
    const remaining = Math.max(0, Math.floor(max - weighted));
    return {
      allowed,
      limit: max,
      remaining,
      resetAt: hit.resetAt,
      used: weighted,
    };
  }

  // fixed
  const allowed = hit.current <= max;
  const remaining = Math.max(0, max - hit.current);
  return {
    allowed,
    limit: max,
    remaining,
    resetAt: hit.resetAt,
    used: hit.current,
  };
}

function applyHeaders(
  res: Response,
  decision: ResolvedDecision,
  now: number,
): void {
  const resetSeconds = Math.max(0, Math.ceil((decision.resetAt - now) / 1000));
  res.setHeader('RateLimit-Limit', String(decision.limit));
  res.setHeader('RateLimit-Remaining', String(decision.remaining));
  res.setHeader('RateLimit-Reset', String(resetSeconds));
}

function rejectRequest(
  req: Request,
  res: Response,
  decision: ResolvedDecision,
  key: string,
  config: RateLimiterConfig,
  emitHeaders: boolean,
  now: number,
): void {
  const retryAfterSeconds = Math.max(
    0,
    Math.ceil((decision.resetAt - now) / 1000),
  );
  if (emitHeaders) {
    applyHeaders(res, decision, now);
    res.setHeader('Retry-After', String(retryAfterSeconds));
  }
  // A misbehaving onLimit hook must NEVER convert a 429 into an allow. Catch a
  // synchronous throw, and attach a rejection handler to a returned promise so
  // an async hook can't produce an unhandled rejection.
  if (config.onLimit) {
    const logger = config.logger ?? consoleLogger;
    try {
      const maybePromise = config.onLimit(req, key) as unknown;
      if (
        maybePromise &&
        typeof (maybePromise as Promise<unknown>).then === 'function'
      ) {
        (maybePromise as Promise<unknown>).catch((err) =>
          logger.warn('[express-security-kit] onLimit hook rejected', err),
        );
      }
    } catch (err) {
      logger.warn('[express-security-kit] onLimit hook threw', err);
    }
  }
  res.status(429).json(
    resolveResponseBody(req, decision, key, retryAfterSeconds, config),
  );
}

const DEFAULT_RATE_LIMIT_MESSAGE = 'Too many requests. Please retry later.';

/** Build the default 429 envelope, optionally with a custom message. */
function defaultBody(retryAfterSeconds: number, message?: string): unknown {
  return {
    error: {
      code: 'RATE_LIMITED',
      message: message ?? DEFAULT_RATE_LIMIT_MESSAGE,
      retryAfter: retryAfterSeconds,
    },
  };
}

/**
 * Resolve the 429 JSON body per precedence: `buildResponseBody` (fully custom)
 * > `message` (default envelope, custom message) > default. A throwing
 * `buildResponseBody` falls back to the default body (logged) so a formatter
 * can never crash the middleware.
 */
/** Log a warning without ever letting a throwing logger break the response. */
function safeWarn(config: RateLimiterConfig, message: string, err: unknown): void {
  try {
    (config.logger ?? consoleLogger).warn(message, err);
  } catch {
    // A logger that throws must not prevent the default body from being sent.
  }
}

function resolveResponseBody(
  req: Request,
  decision: ResolvedDecision,
  key: string,
  retryAfterSeconds: number,
  config: RateLimiterConfig,
): unknown {
  if (config.buildResponseBody) {
    try {
      const custom = config.buildResponseBody({
        limit: decision.limit,
        remaining: decision.remaining,
        resetAt: decision.resetAt,
        retryAfterSeconds,
        key,
        req,
      });
      // A nullish return is treated as "no custom body" rather than sending an
      // empty 429 — guards against a formatter that forgets to return.
      if (custom !== undefined && custom !== null) {
        // The body is resolved synchronously and handed straight to res.json, so
        // a custom body must never be able to break the 429. Reject a thenable
        // (an async formatter would serialize as `{}` and could leak a rejected
        // promise) and anything not JSON-serializable (a circular object or
        // BigInt would make res.json throw into Express's error path).
        if (typeof (custom as { then?: unknown }).then === 'function') {
          throw new Error('buildResponseBody must be synchronous (returned a thenable)');
        }
        JSON.stringify(custom);
        return custom;
      }
    } catch (err) {
      safeWarn(
        config,
        '[express-security-kit] buildResponseBody produced an invalid body; using default',
        err,
      );
    }
  }
  return defaultBody(retryAfterSeconds, config.message);
}

/**
 * For an ALLOWED request under `skipSuccessful`, hook the response and, when it
 * FINISHES with a status < 400, refund the counted hit via `store.decrement`.
 *
 * Refunds ONLY on `finish` (the response was fully sent and the status is
 * final). `close` is used for listener CLEANUP ONLY — never a refund: a client
 * that aborts mid-request emits `close` while `res.statusCode` is still the
 * default 200, so refunding there would credit a request that never completed
 * (e.g. a failed login the route hadn't yet marked 401).
 *
 * `refundFlag` is unique PER LIMITER (not per response), so when several tiers
 * each counted the same successful request, each refunds its own hit; the flag
 * only prevents this one limiter's finish/close pair from acting twice.
 * Never throws.
 */
function scheduleRefundOnSuccess(
  res: Response,
  store: RateLimitStore,
  key: string,
  windowMs: number,
  now: number,
  config: RateLimiterConfig,
  refundFlag: symbol,
): void {
  const bag = res as unknown as Record<symbol, boolean>;
  const cleanup = (): void => {
    res.removeListener('finish', onFinish);
    res.removeListener('close', onClose);
  };
  const onFinish = (): void => {
    if (bag[refundFlag]) return;
    bag[refundFlag] = true;
    cleanup();
    try {
      if (res.statusCode < 400) {
        void Promise.resolve(store.decrement(key, windowMs, now)).catch((err) =>
          safeWarn(config, '[express-security-kit] rate-limit refund failed', err),
        );
      }
    } catch (err) {
      safeWarn(config, '[express-security-kit] rate-limit refund failed', err);
    }
  };
  const onClose = (): void => {
    // Socket closed before `finish` — the response is incomplete/aborted, so do
    // NOT refund; just settle this limiter and drop the listeners.
    if (bag[refundFlag]) return;
    bag[refundFlag] = true;
    cleanup();
  };
  try {
    res.on('finish', onFinish);
    res.on('close', onClose);
  } catch (err) {
    safeWarn(config, '[express-security-kit] could not hook response for refund', err);
  }
}

function buildSingleLimiter(config: RateLimiterConfig): RequestHandler {
  const algorithm = config.algorithm ?? 'fixed';
  const keyGenerator = config.keyGenerator ?? defaultKeyGenerator;
  const store = config.store ?? getSharedStore();
  const emitHeaders = config.headers ?? true;
  const clock = config.now ?? Date.now;
  // Unique per THIS limiter so tiered limiters each refund their own counted
  // hit (a per-response flag would let only the first tier refund).
  const refundFlag = Symbol('express-security-kit.rateLimitRefund');
  const overrideResolver =
    config.overrideResolver ??
    ((req: Request) => req.securityContext?.rateLimitOverride);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (config.skip?.(req)) {
        return next();
      }

      const now = clock();
      const override = overrideResolver(req);
      const { windowMs, max } = resolveMax(config, req, override);
      const key = keyGenerator(req);

      let hit;
      try {
        hit = await store.hit(key, windowMs, now);
      } catch (err) {
        // Fail OPEN: never let a store outage take down the service. safeWarn so
        // a throwing custom logger can't turn a store blip into a 500.
        safeWarn(
          config,
          '[express-security-kit] rate-limit store error; failing open',
          err,
        );
        return next();
      }

      const decision = decide(algorithm, hit, windowMs, max, now);

      if (!decision.allowed) {
        return rejectRequest(
          req,
          res,
          decision,
          key,
          config,
          emitHeaders,
          now,
        );
      }

      if (emitHeaders) {
        applyHeaders(res, decision, now);
      }
      if (config.skipSuccessful) {
        scheduleRefundOnSuccess(res, store, key, windowMs, now, config, refundFlag);
      }
      return next();
    } catch (err) {
      // Any unexpected error also fails open (safeWarn so a throwing logger
      // can't prevent next()).
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
