import type { HitResult, RateLimitStore } from './store';
/**
 * Minimal structural subset of the ioredis client this store uses. Declaring it
 * locally means we do NOT import ioredis's types at the type level either, so
 * the core stays free of a hard ioredis dependency. Pass a real ioredis
 * instance (or an ioredis-compatible client) at construction.
 */
export interface RedisLikeClient {
    incr(key: string): Promise<number>;
    pexpire(key: string, ms: number): Promise<unknown>;
    get(key: string): Promise<string | null>;
    del(...keys: string[]): Promise<unknown>;
}
export interface RedisRateLimitStoreOptions {
    /** Key prefix. Default 'esk:rl'. */
    keyPrefix?: string;
}
/**
 * Redis-backed rate-limit store for multi-instance deployments.
 *
 * Windows are aligned to `windowMs` boundaries. For each key we track two
 * bucket counters keyed by window index:
 *   <prefix>:<key>:<windowIndex>
 * INCR increments the current window (with a PEXPIRE of ~2 windows so the
 * previous bucket survives long enough to be read), and we GET the previous
 * window's counter for the sliding estimate.
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
    hit(key: string, windowMs: number, now: number): Promise<HitResult>;
    /**
     * Clear a key's buckets.
     *
     * LIMITATION: the {@link RateLimitStore} interface gives `reset` no windowMs,
     * so this only deletes the current+previous buckets for a fixed set of COMMON
     * window sizes ({@link RESET_WINDOW_GUESSES}: 1s, 1m, 15m, 1h, 1d) rather than
     * running a heavier SCAN. If your limiter uses a CUSTOM window size not in
     * that list, its buckets are NOT cleared and the key may remain limited until
     * the window naturally expires. Callers needing an exact reset for a custom
     * window should delete their own bucket keys
     * (`<keyPrefix>:<key>:<floor(now/windowMs)>` and the previous index).
     */
    reset(key: string): Promise<void>;
}
