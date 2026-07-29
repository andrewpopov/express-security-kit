import type { SecurityRequest } from '../http';
import { MemoryRateLimitStore, RateLimitStore } from './store';
import {
  defaultKeyGenerator,
  verifiedIdentityKeyResolved,
  KeyGeneratorCore,
  ClientIpResolutionOptions,
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
export interface RateLimitRejectionCore<Req extends SecurityRequest = SecurityRequest> {
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfterSeconds: number;
  key: string;
  req: Req;
}

export interface RateLimiterConfigCore<Req extends SecurityRequest = SecurityRequest> {
  /** Window length in ms. */
  windowMs: number;
  /** Max requests per window. A function receives the request for role-aware limits. */
  max: number | ((req: Req) => number);
  /** 'fixed' (default) or 'sliding' window counter. */
  algorithm?: RateLimitAlgorithm;
  /** Key generator. Default: verifiedIdentityKey (aka defaultKeyGenerator). */
  keyGenerator?: KeyGeneratorCore<Req>;
  /**
   * OPT-IN client-IP trust options applied to the DEFAULT key generator
   * (verifiedIdentityKey falling back to ipKey, resolved via
   * `resolveClientIp`) when no explicit `keyGenerator` is given. Use this
   * behind Cloudflare/cloudflared, where `req.ip` alone either collapses
   * every caller into one bucket (no `trust proxy`) or is bypassable via a
   * forged `X-Forwarded-For` first hop (`trust proxy: true`). Ignored
   * entirely when `keyGenerator` is set — bring-your-own-generator always
   * wins. Omitting this leaves keying byte-for-byte identical to pre-1.4.0
   * behavior (`req.ip` via the untouched `defaultKeyGenerator`).
   */
  ipResolution?: ClientIpResolutionOptions;
  /** Backing store. Default: a shared in-process MemoryRateLimitStore. */
  store?: RateLimitStore;
  /**
   * Resolve a per-request override. Default reads
   * `req.securityContext?.rateLimitOverride`. Return undefined for no override.
   */
  overrideResolver?: (req: Req) => RateLimitOverride | undefined;
  /** Skip limiting entirely for a request (e.g. health checks, dev mode). */
  skip?: (req: Req) => boolean;
  /**
   * Called when a request is rejected with 429. May be async. A throw or a
   * rejected promise is swallowed (logged) and NEVER prevents the 429.
   */
  onLimit?: (req: Req, key: string) => void | Promise<unknown>;
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
  buildResponseBody?: (info: RateLimitRejectionCore<Req>) => unknown;
  /**
   * When true, REFUND (decrement) the counted hit for a request that ends with
   * a status < 400, so only failed requests count toward the limit — mirrors
   * express-rate-limit's `skipSuccessfulRequests` (e.g. an auth limiter where
   * only failed logins should count). The refund fires once on response
   * `finish` (a genuinely completed response); a `close` without `finish` is an
   * aborted request and is NOT refunded. Default false. Requires a store that
   * implements `decrement` (the built-in Memory and Redis stores do).
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

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  /** Effective count used for the decision (weighted for sliding). */
  used: number;
}

/** A response header the adapter should emit, as [name, value]. */
export type RateLimitHeader = readonly [name: string, value: string];

export type RateLimitOutcome<Req extends SecurityRequest = SecurityRequest> =
  | {
      /** Do not limit this request; let it proceed. `headers` is always empty. */
      type: 'skip';
      reason: 'skipped' | 'store-error' | 'unexpected-error';
    }
  | {
      type: 'allow';
      key: string;
      windowMs: number;
      decision: RateLimitDecision;
      /** Empty when `headers: false`. Emit in order. */
      headers: RateLimitHeader[];
      /**
       * Present ONLY when `skipSuccessful` is set. The adapter calls this
       * exactly once, with the final status code, when the response has
       * genuinely FINISHED. Applies the <400 policy itself. Never throws.
       */
      onSettled?: (statusCode: number) => void;
    }
  | {
      type: 'reject';
      key: string;
      windowMs: number;
      decision: RateLimitDecision;
      /** Includes Retry-After. Empty when `headers: false`. Emit in order. */
      headers: RateLimitHeader[];
      status: 429;
      body: unknown;
      /**
       * The body, already `JSON.stringify`d exactly once by the core (which
       * also validated it as part of resolving the body). Adapters that send
       * JSON text directly (e.g. Fastify) MUST send this instead of
       * re-stringifying `body` themselves — re-serializing risks producing
       * different bytes (or throwing) if the value is stateful (a getter or a
       * `toJSON` with side effects). Express's `res.json(body)` does its own
       * serialization by design and is exempt from this.
       */
      serializedBody: string;
      retryAfterSeconds: number;
    };

export interface RateLimitCore<Req extends SecurityRequest = SecurityRequest> {
  /** NEVER throws and never rejects — any internal failure fails OPEN as a
   *  `skip` outcome, matching the pre-carve middleware. */
  evaluate(req: Req): Promise<RateLimitOutcome<Req>>;
  /** The store actually in use (config's, or the shared default). */
  readonly store: RateLimitStore;
}

function resolveMax<Req extends SecurityRequest>(
  config: RateLimiterConfigCore<Req>,
  req: Req,
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
): RateLimitDecision {
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

/** The RateLimit-* header VALUES for a decision; order matches emission order. */
function computeHeaderValues(decision: RateLimitDecision, now: number): RateLimitHeader[] {
  const resetSeconds = Math.max(0, Math.ceil((decision.resetAt - now) / 1000));
  return [
    ['RateLimit-Limit', String(decision.limit)],
    ['RateLimit-Remaining', String(decision.remaining)],
    ['RateLimit-Reset', String(resetSeconds)],
  ];
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

/** Log a warning without ever letting a throwing logger break the response. */
export function safeWarn<Req extends SecurityRequest = SecurityRequest>(
  config: RateLimiterConfigCore<Req>,
  message: string,
  err: unknown,
): void {
  try {
    (config.logger ?? consoleLogger).warn(message, err);
  } catch {
    // A logger that throws must not prevent the default body from being sent.
  }
}

/** The 429 body plus its serialization, computed exactly once. */
interface ResolvedResponseBody {
  body: unknown;
  serializedBody: string;
}

/**
 * Resolve the 429 JSON body per precedence: `buildResponseBody` (fully custom)
 * > `message` (default envelope, custom message) > default. A throwing
 * `buildResponseBody` falls back to the default body (logged) so a formatter
 * can never crash the middleware. Serializes the chosen body exactly ONCE —
 * the returned `serializedBody` is what adapters that write JSON text
 * directly must send, so a body is never re-stringified (and thus never
 * re-evaluated, which matters for a stateful `toJSON` or getter) after this
 * function has validated it.
 */
function resolveResponseBody<Req extends SecurityRequest>(
  req: Req,
  decision: RateLimitDecision,
  key: string,
  retryAfterSeconds: number,
  config: RateLimiterConfigCore<Req>,
): ResolvedResponseBody {
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
        // The body is resolved synchronously and handed straight to the
        // adapter's response write, so a custom body must never be able to
        // break the 429. Reject a thenable (an async formatter would
        // serialize as `{}` and could leak a rejected promise) and anything
        // not JSON-serializable (a circular object or BigInt would make the
        // adapter's JSON write throw into its own error path).
        if (typeof (custom as { then?: unknown }).then === 'function') {
          throw new Error('buildResponseBody must be synchronous (returned a thenable)');
        }
        const serializedBody = JSON.stringify(custom);
        // `JSON.stringify` returns `undefined` WITHOUT throwing for a
        // top-level function, a symbol, or an object whose `toJSON()`
        // returns `undefined` — that must be treated the same as a throw,
        // not as success, or the adapter ends up sending an empty body.
        if (serializedBody === undefined) {
          throw new Error(
            'buildResponseBody must return a JSON-serializable value',
          );
        }
        return { body: custom, serializedBody };
      }
    } catch (err) {
      safeWarn(
        config,
        '[express-security-kit] buildResponseBody produced an invalid body; using default',
        err,
      );
    }
  }
  const body = defaultBody(retryAfterSeconds, config.message);
  // `defaultBody` always returns a plain, JSON-serializable object literal,
  // so `JSON.stringify` here can never return `undefined`.
  return { body, serializedBody: JSON.stringify(body)! };
}

/**
 * The response surface the refund hook needs. Both an Express `Response` and
 * a Fastify `reply.raw` are a Node `http.ServerResponse`, which satisfies
 * this structurally — so the finish-vs-close distinction is written once.
 */
export interface RefundableResponse {
  statusCode: number;
  on(event: 'finish' | 'close', listener: () => void): unknown;
  removeListener(event: 'finish' | 'close', listener: () => void): unknown;
}

/**
 * For an ALLOWED request under `skipSuccessful`, hook the response and, when it
 * FINISHES with a status < 400, refund the counted hit via `onSettled` (which
 * applies the store.decrement policy).
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
export function scheduleRefundOnFinish(
  res: RefundableResponse,
  onSettled: (statusCode: number) => void,
  refundFlag: symbol,
  onHookError: (err: unknown) => void,
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
    onSettled(res.statusCode);
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
    onHookError(err);
  }
}

/**
 * Build the framework-agnostic rate-limit decision engine. `evaluate` mirrors
 * the pre-carve Express middleware's control flow exactly (see the ordering
 * notes on each branch below) but performs NO framework I/O — no headers are
 * written, no response is sent, no `next()` is called. The adapter (Express,
 * Fastify, ...) is responsible for translating a `RateLimitOutcome` into the
 * actual response.
 */
export function createRateLimitCore<Req extends SecurityRequest = SecurityRequest>(
  config: RateLimiterConfigCore<Req>,
): RateLimitCore<Req> {
  const algorithm = config.algorithm ?? 'fixed';
  // `ipResolution` only takes effect when no explicit `keyGenerator` is
  // given — an explicit generator is always authoritative. With neither set,
  // this is `defaultKeyGenerator` untouched, preserving pre-1.4.0 keys.
  const keyGenerator: KeyGeneratorCore<Req> =
    config.keyGenerator ??
    (config.ipResolution
      ? verifiedIdentityKeyResolved<Req>(config.ipResolution)
      : defaultKeyGenerator);
  const store = config.store ?? getSharedStore();
  const emitHeaders = config.headers ?? true;
  const clock = config.now ?? Date.now;
  const overrideResolver =
    config.overrideResolver ??
    ((req: Req) => req.securityContext?.rateLimitOverride);

  async function evaluate(req: Req): Promise<RateLimitOutcome<Req>> {
    try {
      if (config.skip?.(req)) {
        return { type: 'skip', reason: 'skipped' };
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
        return { type: 'skip', reason: 'store-error' };
      }

      const decision = decide(algorithm, hit, windowMs, max, now);

      if (!decision.allowed) {
        const retryAfterSeconds = Math.max(
          0,
          Math.ceil((decision.resetAt - now) / 1000),
        );
        const headers: RateLimitHeader[] = emitHeaders
          ? [...computeHeaderValues(decision, now), ['Retry-After', String(retryAfterSeconds)]]
          : [];

        // A misbehaving onLimit hook must NEVER convert a 429 into an allow.
        // Catch a synchronous throw, and attach a rejection handler to a
        // returned promise so an async hook can't produce an unhandled
        // rejection. Fires before the outcome is returned (i.e. before the
        // adapter writes headers) — both are synchronous and onLimit never
        // touches the response, so this is unobservable.
        if (config.onLimit) {
          try {
            const maybePromise = config.onLimit(req, key) as unknown;
            if (
              maybePromise &&
              typeof (maybePromise as Promise<unknown>).then === 'function'
            ) {
              (maybePromise as Promise<unknown>).catch((err) =>
                safeWarn(config, '[express-security-kit] onLimit hook rejected', err),
              );
            }
          } catch (err) {
            safeWarn(config, '[express-security-kit] onLimit hook threw', err);
          }
        }

        const { body, serializedBody } = resolveResponseBody(
          req,
          decision,
          key,
          retryAfterSeconds,
          config,
        );

        return {
          type: 'reject',
          key,
          windowMs,
          decision,
          headers,
          status: 429,
          body,
          serializedBody,
          retryAfterSeconds,
        };
      }

      const headers: RateLimitHeader[] = emitHeaders
        ? computeHeaderValues(decision, now)
        : [];

      if (config.skipSuccessful) {
        // The refund POLICY only — the adapter decides WHEN this is safe to
        // call (i.e. once, on a genuinely finished response). Errors from the
        // store are swallowed via safeWarn; a refund must never surface as a
        // thrown error to the caller.
        const onSettled = (statusCode: number): void => {
          try {
            if (statusCode < 400) {
              void Promise.resolve(store.decrement(key, windowMs, now)).catch((err) =>
                safeWarn(config, '[express-security-kit] rate-limit refund failed', err),
              );
            }
          } catch (err) {
            safeWarn(config, '[express-security-kit] rate-limit refund failed', err);
          }
        };
        return { type: 'allow', key, windowMs, decision, headers, onSettled };
      }

      return { type: 'allow', key, windowMs, decision, headers };
    } catch (err) {
      // Any unexpected error also fails open (safeWarn so a throwing logger
      // can't prevent the caller from proceeding).
      safeWarn(
        config,
        '[express-security-kit] rate-limit unexpected error; failing open',
        err,
      );
      return { type: 'skip', reason: 'unexpected-error' };
    }
  }

  return { evaluate, store };
}
