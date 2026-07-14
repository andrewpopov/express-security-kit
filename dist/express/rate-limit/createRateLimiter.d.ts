import type { Request, RequestHandler } from 'express';
import { RateLimitStore } from '../../core/rate-limit/store';
import { KeyGeneratorCore, ClientIpResolutionOptions } from '../../core/rate-limit/keyGenerator';
/** Express-pinned alias: same shape as the pre-carve `KeyGenerator`. */
export type KeyGenerator = KeyGeneratorCore<Request>;
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
/**
 * Create an Express rate-limit middleware.
 *
 * Pass a single config, or an ARRAY of tier configs applied in sequence — the
 * first tier to exceed its limit rejects the request (this is what enables the
 * recommended layered pattern: a coarse per-IP flood tier + a per-principal
 * fair-share tier). Each tier is independent; give tiers distinct stores/keys.
 */
export declare function createRateLimiter(config: RateLimiterConfig | RateLimiterConfig[]): RequestHandler;
