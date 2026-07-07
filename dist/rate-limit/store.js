"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryRateLimitStore = void 0;
const DEFAULT_CLEANUP_INTERVAL_MS = 60000;
const DEFAULT_MAX_TRACKED_KEYS = 100000;
/**
 * In-memory, single-process rate-limit store. Suitable for a single Node
 * instance. For multi-instance deployments use the Redis store.
 *
 * Windows are aligned to `windowMs` boundaries (`floor(now / windowMs)`), so a
 * key's previous-window count is well defined for the sliding estimate. A
 * periodic `.unref()`'d timer evicts buckets untouched for two window lengths,
 * and a `MAX_TRACKED_KEYS` cap triggers drop-oldest eviction to bound memory.
 */
class MemoryRateLimitStore {
    constructor(options = {}) {
        this.buckets = new Map();
        this.cleanupIntervalMs =
            options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL_MS;
        this.maxTrackedKeys = options.maxTrackedKeys ?? DEFAULT_MAX_TRACKED_KEYS;
        this.startTimer();
    }
    startTimer() {
        if (this.timer)
            return;
        this.timer = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
        // Do not keep the event loop alive on account of this housekeeping timer.
        this.timer.unref?.();
    }
    async hit(key, windowMs, now) {
        const windowStart = Math.floor(now / windowMs) * windowMs;
        const resetAt = windowStart + windowMs;
        // Namespace buckets by BOTH key and windowMs so two limiters that share
        // this store but use different window lengths (even with the same key)
        // never clobber each other's counters.
        const bucketKey = `${key}::${windowMs}`;
        let bucket = this.buckets.get(bucketKey);
        if (!bucket) {
            bucket = {
                windowStart,
                windowMs,
                current: 0,
                previous: 0,
                lastSeen: now,
            };
        }
        else {
            // Re-insert to refresh insertion order for drop-oldest eviction.
            this.buckets.delete(bucketKey);
            this.rollWindow(bucket, windowStart);
        }
        bucket.current += 1;
        bucket.lastSeen = now;
        this.buckets.set(bucketKey, bucket);
        this.evictIfNeeded();
        return { current: bucket.current, previous: bucket.previous, resetAt };
    }
    /**
     * Advance a bucket to the target window. Because buckets are namespaced by
     * windowMs, every bucket always has the same window length, so this only ever
     * moves forward in time. If the target is exactly one window ahead, the
     * current count becomes `previous`; a larger gap means the previous window is
     * stale, so `previous` resets to zero. A same-or-earlier window is a no-op.
     */
    rollWindow(bucket, windowStart) {
        if (windowStart <= bucket.windowStart) {
            return;
        }
        const windowsElapsed = Math.round((windowStart - bucket.windowStart) / bucket.windowMs);
        bucket.previous = windowsElapsed === 1 ? bucket.current : 0;
        bucket.current = 0;
        bucket.windowStart = windowStart;
    }
    async reset(key, windowMs) {
        if (windowMs !== undefined) {
            // Precise reset: delete only the bucket for this exact window length.
            this.buckets.delete(`${key}::${windowMs}`);
            return;
        }
        // Buckets are namespaced as `${key}::${windowMs}`, so clear every window
        // bucket belonging to this key.
        const prefix = `${key}::`;
        for (const bucketKey of this.buckets.keys()) {
            if (bucketKey.startsWith(prefix)) {
                this.buckets.delete(bucketKey);
            }
        }
    }
    evictIfNeeded() {
        while (this.buckets.size > this.maxTrackedKeys) {
            // Map preserves insertion order; the first key is the oldest.
            const oldest = this.buckets.keys().next().value;
            if (oldest === undefined)
                break;
            this.buckets.delete(oldest);
        }
    }
    cleanup() {
        const now = Date.now();
        for (const [key, bucket] of this.buckets) {
            if (now - bucket.lastSeen > bucket.windowMs * 2) {
                this.buckets.delete(key);
            }
        }
    }
    /** Clear the cleanup timer. Alias of dispose() for ergonomic test teardown. */
    stop() {
        this.dispose();
    }
    dispose() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = undefined;
        }
    }
    /** Test/introspection helper: number of tracked keys. */
    get size() {
        return this.buckets.size;
    }
}
exports.MemoryRateLimitStore = MemoryRateLimitStore;
