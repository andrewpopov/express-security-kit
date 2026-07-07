"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisRateLimitStore = void 0;
/**
 * Atomic hit script. KEYS = [currentKey, previousKey]; ARGV = [String(windowMs*2)].
 *
 * `PTTL(K) < 0` covers BOTH "fresh key, no TTL yet" and "a key leaked by the old
 * non-atomic path (or a previous crash) that never got its TTL set" — either way
 * we (re)arm the TTL. We do this for the CURRENT key (always exists after INCR)
 * AND for the PREVIOUS key when it exists, so a counter leaked in an earlier
 * window is healed the one time it is read as "previous" rather than living
 * forever. (PTTL returns -1 for a key with no expiry, -2 for a missing key.)
 */
const HIT_SCRIPT = `
local c = redis.call('INCR', KEYS[1])
if redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local p = redis.call('GET', KEYS[2])
if p and redis.call('PTTL', KEYS[2]) < 0 then redis.call('PEXPIRE', KEYS[2], ARGV[1]) end
return { c, p or '0' }
`;
/**
 * Atomic refund script. KEYS = [currentKey]. Decrements only when the counter
 * exists and is > 0, so it never creates a phantom key or drives a counter
 * negative (a bare DECR on a missing key would set it to -1). Returns the value
 * after the (possible) decrement.
 */
const DECREMENT_SCRIPT = `
local v = tonumber(redis.call('GET', KEYS[1]))
if v and v > 0 then return redis.call('DECR', KEYS[1]) end
return v or 0
`;
/**
 * Coerce a Lua-script return value to a non-negative integer, or throw. STRICT
 * on purpose: only a real non-negative integer (ioredis returns Lua numbers as
 * JS numbers) or a pure-digit string (GET returns strings) is accepted. `null`,
 * booleans, `''`, whitespace, floats, arrays, and negatives all THROW so a
 * corrupt/unexpected result surfaces as a store error (→ fail open) instead of
 * being silently coerced to 0/1 by `Number()`.
 */
function coerceNonNegativeInt(value, label) {
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
        return value;
    }
    if (typeof value === 'string' && /^\d+$/.test(value)) {
        return Number.parseInt(value, 10);
    }
    throw new Error(`RedisRateLimitStore: malformed eval result (${label}=${JSON.stringify(value)})`);
}
/**
 * Strictly parse the `[current, previous]` result of {@link HIT_SCRIPT}. THROWS
 * (rather than silently coercing with `|| 0`) on any malformed shape or value
 * so a corrupted/unexpected eval result surfaces as a store error —
 * `createRateLimiter` catches that and fails OPEN, which is the desired
 * behavior for a rate-limit store outage/anomaly.
 */
function parseHitResult(result) {
    if (!Array.isArray(result) || result.length < 2) {
        throw new Error(`RedisRateLimitStore: malformed eval result (expected an array of length >= 2, got ${JSON.stringify(result)})`);
    }
    return {
        current: coerceNonNegativeInt(result[0], 'current'),
        previous: coerceNonNegativeInt(result[1], 'previous'),
    };
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
class RedisRateLimitStore {
    constructor(client, options = {}) {
        this.client = client;
        this.keyPrefix = options.keyPrefix ?? 'esk:rl';
    }
    bucketKey(key, windowMs, windowIndex) {
        return `${this.keyPrefix}:${key}:${windowMs}:${windowIndex}`;
    }
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
    async hit(key, windowMs, now) {
        const windowIndex = Math.floor(now / windowMs);
        const windowStart = windowIndex * windowMs;
        const resetAt = windowStart + windowMs;
        const currentKey = this.bucketKey(key, windowMs, windowIndex);
        const previousKey = this.bucketKey(key, windowMs, windowIndex - 1);
        if (typeof this.client.eval === 'function') {
            const result = await this.client.eval(HIT_SCRIPT, 2, currentKey, previousKey, String(windowMs * 2));
            const { current, previous } = parseHitResult(result);
            return { current, previous, resetAt };
        }
        // Non-atomic fallback — see the JSDoc above. NOT leak-safe.
        const current = await this.client.incr(currentKey);
        await this.client.pexpire(currentKey, windowMs * 2);
        const previousRaw = await this.client.get(previousKey);
        const previous = previousRaw ? Number.parseInt(previousRaw, 10) || 0 : 0;
        return { current, previous, resetAt };
    }
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
    async reset(key, windowMs) {
        const now = Date.now();
        if (windowMs !== undefined) {
            const windowIndex = Math.floor(now / windowMs);
            await this.client.del(this.bucketKey(key, windowMs, windowIndex), this.bucketKey(key, windowMs, windowIndex - 1));
            return;
        }
        const keysToDelete = [];
        for (const guessWindowMs of RESET_WINDOW_GUESSES) {
            const idx = Math.floor(now / guessWindowMs);
            keysToDelete.push(this.bucketKey(key, guessWindowMs, idx), this.bucketKey(key, guessWindowMs, idx - 1));
        }
        await this.client.del(...keysToDelete);
    }
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
    async decrement(key, windowMs, now = Date.now()) {
        if (windowMs !== undefined) {
            const windowIndex = Math.floor(now / windowMs);
            await this.decrementBucket(this.bucketKey(key, windowMs, windowIndex));
            return;
        }
        for (const guessWindowMs of RESET_WINDOW_GUESSES) {
            const idx = Math.floor(now / guessWindowMs);
            await this.decrementBucket(this.bucketKey(key, guessWindowMs, idx));
        }
    }
    /** Decrement a single bucket key iff it exists and is > 0. Never negative. */
    async decrementBucket(bucketKey) {
        if (typeof this.client.eval === 'function') {
            await this.client.eval(DECREMENT_SCRIPT, 1, bucketKey);
            return;
        }
        // Non-atomic fallback (test doubles without eval).
        const raw = await this.client.get(bucketKey);
        const value = raw ? Number.parseInt(raw, 10) || 0 : 0;
        if (value > 0) {
            await this.client.decr(bucketKey);
        }
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
