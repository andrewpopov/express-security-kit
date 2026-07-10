import type { HitResult, RateLimitStore } from './store';
/**
 * Minimal structural subset of the ioredis client this store uses. Declaring it
 * locally means we do NOT import ioredis's types at the type level either, so
 * the core stays free of a hard ioredis dependency. Pass a real ioredis
 * instance (or an ioredis-compatible client) at construction.
 */
export interface RedisLikeClient {
    incr(key: string): Promise<number>;
    decr(key: string): Promise<number>;
    pexpire(key: string, ms: number): Promise<unknown>;
    get(key: string): Promise<string | null>;
    del(...keys: string[]): Promise<unknown>;
    /**
     * OPTIONAL: run a Lua script atomically. Real ioredis always implements this.
     * When present, `hit()` uses it for an atomic INCR+PEXPIRE+GET (one round
     * trip, no torn leak window). When absent, `hit()` falls back to the
     * non-atomic 3-call path (see the JSDoc on {@link RedisRateLimitStore.hit}).
     */
    eval?(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
}
export interface RedisRateLimitStoreOptions {
    /** Key prefix. Default 'esk:rl'. */
    keyPrefix?: string;
}
/**
 * Redis-backed rate-limit store for multi-instance deployments.
 *
 * Windows are aligned to `windowMs` boundaries. For each key we track two
 * bucket counters keyed by BOTH window length and window index:
 *   <prefix>:<key>:<windowMs>:<windowIndex>
 * (namespacing by `windowMs` mirrors {@link MemoryRateLimitStore}, so two
 * limiters sharing a store/key with different window lengths never collide).
 *
 * This is the ONLY file that depends on a Redis client, and it is the
 * `@andrewpopov/express-security-kit/redis-store` subpath export. The main
 * entry (`index.ts`) never imports it, keeping the core dependency-free.
 */
export declare class RedisRateLimitStore implements RateLimitStore {
    private readonly client;
    private readonly keyPrefix;
    constructor(client: RedisLikeClient, options?: RedisRateLimitStoreOptions);
    private bucketKey;
    /**
     * Record a hit. When the client implements `eval`, this runs ONE atomic Lua
     * round trip ({@link HIT_SCRIPT}): INCR + (re)arm-TTL-if-unset + GET previous.
     * Because Lua scripts execute atomically in Redis, INCR and PEXPIRE can never
     * be torn by a crash — the never-expiring-key leak is fixed, and the script
     * also self-heals any key already leaked by the fallback path below.
     *
     * When the client does NOT implement `eval` (e.g. a minimal hand-rolled
     * fake), this falls back to the ORIGINAL 3-call path: INCR, then a SEPARATE
     * PEXPIRE, then GET. This fallback is explicitly NON-ATOMIC and does NOT fix
     * the leak — a crash between INCR and PEXPIRE still leaves a key with no TTL.
     * Real ioredis clients always implement `eval`, so production traffic always
     * takes the atomic path; the fallback exists only for eval-less test doubles.
     */
    hit(key: string, windowMs: number, now: number): Promise<HitResult>;
    /**
     * Clear a key's bucket(s).
     *
     * With `windowMs`: deletes the EXACT current+previous buckets for that
     * window — precise, no guessing.
     *
     * Without `windowMs` (back-compat): falls back to a fixed set of common
     * window sizes ({@link RESET_WINDOW_GUESSES}: 1s, 1m, 15m, 1h, 1d) rather
     * than running a heavier SCAN. If your limiter uses a CUSTOM window size not
     * in that list, its buckets are NOT cleared and the key may remain limited
     * until the window naturally expires — pass `windowMs` for an exact reset.
     */
    reset(key: string, windowMs?: number): Promise<void>;
    /**
     * Refund a hit by decrementing the current-window bucket, floored at 0.
     *
     * With `windowMs`/`now` (as `createRateLimiter` passes — the SAME values used
     * for the matching `hit`), targets the EXACT bucket that was incremented.
     * Without them, decrements the current bucket across a fixed set of common
     * window sizes ({@link RESET_WINDOW_GUESSES}) — best-effort, like `reset`.
     *
     * Uses an atomic conditional-DECR Lua script when the client supports `eval`
     * (never creates a phantom key or goes negative); otherwise falls back to a
     * non-atomic GET-then-DECR (test-double path). Never a bare DECR.
     */
    decrement(key: string, windowMs?: number, now?: number): Promise<void>;
    /** Decrement a single bucket key iff it exists and is > 0. Never negative. */
    private decrementBucket;
}
