/**
 * Result of recording a hit against a key for a given window.
 *
 * The shape supports BOTH algorithms:
 *  - fixed  window: uses `current` and `resetAt`.
 *  - sliding window: also uses `previous` (the prior window's final count) to
 *    compute the weighted estimate.
 */
export interface HitResult {
    /** Number of hits recorded in the CURRENT window (including this hit). */
    current: number;
    /** Final count of the PREVIOUS window (0 if there was none). */
    previous: number;
    /** Epoch ms at which the current window ends / the count resets. */
    resetAt: number;
}
export interface RateLimitStore {
    /**
     * Record a hit for `key` in the window of length `windowMs` that contains
     * `now`. Returns the current-window count, the previous-window final count,
     * and the current window's reset time.
     */
    hit(key: string, windowMs: number, now: number): Promise<HitResult>;
    /** Clear all state for a key. */
    reset(key: string): Promise<void>;
    /** Release resources (timers, connections). Safe to call more than once. */
    dispose?(): void;
}
export interface MemoryRateLimitStoreOptions {
    /** How often the cleanup timer fires (ms). Default 60_000. */
    cleanupIntervalMs?: number;
    /** Max number of distinct keys tracked before drop-oldest eviction. */
    maxTrackedKeys?: number;
}
/**
 * In-memory, single-process rate-limit store. Suitable for a single Node
 * instance. For multi-instance deployments use the Redis store.
 *
 * Windows are aligned to `windowMs` boundaries (`floor(now / windowMs)`), so a
 * key's previous-window count is well defined for the sliding estimate. A
 * periodic `.unref()`'d timer evicts buckets untouched for two window lengths,
 * and a `MAX_TRACKED_KEYS` cap triggers drop-oldest eviction to bound memory.
 */
export declare class MemoryRateLimitStore implements RateLimitStore {
    private readonly buckets;
    private readonly cleanupIntervalMs;
    private readonly maxTrackedKeys;
    private timer;
    constructor(options?: MemoryRateLimitStoreOptions);
    private startTimer;
    hit(key: string, windowMs: number, now: number): Promise<HitResult>;
    /**
     * Advance a bucket to the target window. Because buckets are namespaced by
     * windowMs, every bucket always has the same window length, so this only ever
     * moves forward in time. If the target is exactly one window ahead, the
     * current count becomes `previous`; a larger gap means the previous window is
     * stale, so `previous` resets to zero. A same-or-earlier window is a no-op.
     */
    private rollWindow;
    reset(key: string): Promise<void>;
    private evictIfNeeded;
    private cleanup;
    /** Clear the cleanup timer. Alias of dispose() for ergonomic test teardown. */
    stop(): void;
    dispose(): void;
    /** Test/introspection helper: number of tracked keys. */
    get size(): number;
}
