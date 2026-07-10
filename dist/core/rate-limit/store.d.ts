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
    /**
     * Clear state for a key. When `windowMs` is given, clears ONLY that window's
     * bucket(s) — precise, no guessing. When omitted, clears every window bucket
     * tracked for the key (implementation-defined scope; see each store's docs).
     */
    reset(key: string, windowMs?: number): Promise<void>;
    /**
     * Refund a previously-counted hit by decrementing `key`'s current-window
     * counter, flooring at 0. Used by `skipSuccessful` to not count requests that
     * ended successfully. MUST be total/non-throwing and a no-op if the key/window
     * is already gone.
     *
     * `windowMs`/`now` are OPTIONAL — a caller may invoke `decrement(key)` — but
     * when supplied (as `createRateLimiter` does, passing the SAME values it used
     * for the corresponding `hit`) they let a windowed store target the EXACT
     * bucket that was incremented rather than guessing.
     */
    decrement(key: string, windowMs?: number, now?: number): void | Promise<void>;
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
    reset(key: string, windowMs?: number): Promise<void>;
    /**
     * Refund a hit, floored at 0. With `windowMs`/`now` (the SAME values used for
     * the matching `hit`), targets the EXACT sub-counter the hit landed in: the
     * hit incremented the window containing `now`, but by refund time the bucket
     * may have rolled, moving that count into `previous` (exactly one roll) or
     * expiring it (a larger gap). Decrementing `bucket.current` unconditionally
     * would refund an unrelated later request and leave the real hit counted.
     * Without `windowMs`/`now` it best-effort decrements current bucket(s). No-op
     * if the key/window is gone. Never throws.
     */
    decrement(key: string, windowMs?: number, now?: number): void;
    private evictIfNeeded;
    private cleanup;
    /** Clear the cleanup timer. Alias of dispose() for ergonomic test teardown. */
    stop(): void;
    dispose(): void;
    /** Test/introspection helper: number of tracked keys. */
    get size(): number;
}
