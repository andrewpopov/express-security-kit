"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisRateLimitStore = void 0;
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
class RedisRateLimitStore {
    constructor(client, options = {}) {
        this.client = client;
        this.keyPrefix = options.keyPrefix ?? 'esk:rl';
    }
    bucketKey(key, windowIndex) {
        return `${this.keyPrefix}:${key}:${windowIndex}`;
    }
    async hit(key, windowMs, now) {
        const windowIndex = Math.floor(now / windowMs);
        const windowStart = windowIndex * windowMs;
        const resetAt = windowStart + windowMs;
        const currentKey = this.bucketKey(key, windowIndex);
        const previousKey = this.bucketKey(key, windowIndex - 1);
        const current = await this.client.incr(currentKey);
        // Keep the bucket alive for two windows so the sliding estimate can read
        // this window as "previous" during the next window.
        await this.client.pexpire(currentKey, windowMs * 2);
        const previousRaw = await this.client.get(previousKey);
        const previous = previousRaw ? Number.parseInt(previousRaw, 10) || 0 : 0;
        return { current, previous, resetAt };
    }
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
    async reset(key) {
        const now = Date.now();
        const keysToDelete = [];
        for (const windowMs of RESET_WINDOW_GUESSES) {
            const idx = Math.floor(now / windowMs);
            keysToDelete.push(this.bucketKey(key, idx), this.bucketKey(key, idx - 1));
        }
        await this.client.del(...keysToDelete);
    }
}
exports.RedisRateLimitStore = RedisRateLimitStore;
const RESET_WINDOW_GUESSES = [
    1000, // 1s
    60000, // 1m
    900000, // 15m
    3600000, // 1h
    86400000, // 1d
];
