import type { SecurityRequest } from '../http';
import { RateLimitStore } from './store';
import { KeyGeneratorCore, ClientIpResolutionOptions } from './keyGenerator';
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
export type RateLimitOutcome<Req extends SecurityRequest = SecurityRequest> = {
    /** Do not limit this request; let it proceed. `headers` is always empty. */
    type: 'skip';
    reason: 'skipped' | 'store-error' | 'unexpected-error';
} | {
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
} | {
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
/** Log a warning without ever letting a throwing logger break the response. */
export declare function safeWarn<Req extends SecurityRequest = SecurityRequest>(config: RateLimiterConfigCore<Req>, message: string, err: unknown): void;
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
export declare function scheduleRefundOnFinish(res: RefundableResponse, onSettled: (statusCode: number) => void, refundFlag: symbol, onHookError: (err: unknown) => void): void;
/**
 * Build the framework-agnostic rate-limit decision engine. `evaluate` mirrors
 * the pre-carve Express middleware's control flow exactly (see the ordering
 * notes on each branch below) but performs NO framework I/O — no headers are
 * written, no response is sent, no `next()` is called. The adapter (Express,
 * Fastify, ...) is responsible for translating a `RateLimitOutcome` into the
 * actual response.
 */
export declare function createRateLimitCore<Req extends SecurityRequest = SecurityRequest>(config: RateLimiterConfigCore<Req>): RateLimitCore<Req>;
