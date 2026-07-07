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

interface WindowBucket {
  /** Start epoch ms of the current window (aligned to windowMs boundaries). */
  windowStart: number;
  /** Length of the current window. */
  windowMs: number;
  /** Count in the current window. */
  current: number;
  /** Final count of the immediately-preceding window (same length). */
  previous: number;
  /** Last time this bucket was touched, for stale eviction. */
  lastSeen: number;
}

export interface MemoryRateLimitStoreOptions {
  /** How often the cleanup timer fires (ms). Default 60_000. */
  cleanupIntervalMs?: number;
  /** Max number of distinct keys tracked before drop-oldest eviction. */
  maxTrackedKeys?: number;
}

const DEFAULT_CLEANUP_INTERVAL_MS = 60_000;
const DEFAULT_MAX_TRACKED_KEYS = 100_000;

/**
 * In-memory, single-process rate-limit store. Suitable for a single Node
 * instance. For multi-instance deployments use the Redis store.
 *
 * Windows are aligned to `windowMs` boundaries (`floor(now / windowMs)`), so a
 * key's previous-window count is well defined for the sliding estimate. A
 * periodic `.unref()`'d timer evicts buckets untouched for two window lengths,
 * and a `MAX_TRACKED_KEYS` cap triggers drop-oldest eviction to bound memory.
 */
export class MemoryRateLimitStore implements RateLimitStore {
  private readonly buckets = new Map<string, WindowBucket>();
  private readonly cleanupIntervalMs: number;
  private readonly maxTrackedKeys: number;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: MemoryRateLimitStoreOptions = {}) {
    this.cleanupIntervalMs =
      options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL_MS;
    this.maxTrackedKeys = options.maxTrackedKeys ?? DEFAULT_MAX_TRACKED_KEYS;
    this.startTimer();
  }

  private startTimer(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
    // Do not keep the event loop alive on account of this housekeeping timer.
    this.timer.unref?.();
  }

  async hit(key: string, windowMs: number, now: number): Promise<HitResult> {
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
    } else {
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
  private rollWindow(bucket: WindowBucket, windowStart: number): void {
    if (windowStart <= bucket.windowStart) {
      return;
    }

    const windowsElapsed = Math.round(
      (windowStart - bucket.windowStart) / bucket.windowMs,
    );
    bucket.previous = windowsElapsed === 1 ? bucket.current : 0;
    bucket.current = 0;
    bucket.windowStart = windowStart;
  }

  async reset(key: string, windowMs?: number): Promise<void> {
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
  decrement(key: string, windowMs?: number, now?: number): void {
    if (windowMs !== undefined) {
      const bucket = this.buckets.get(`${key}::${windowMs}`);
      if (!bucket) return;
      if (now === undefined) {
        if (bucket.current > 0) bucket.current -= 1;
        return;
      }
      const hitWindowStart = Math.floor(now / windowMs) * windowMs;
      if (bucket.windowStart === hitWindowStart) {
        // Bucket hasn't rolled past the hit's window — the hit is in `current`.
        if (bucket.current > 0) bucket.current -= 1;
      } else if (bucket.windowStart === hitWindowStart + windowMs) {
        // Rolled exactly one window — the hit's count is now in `previous`.
        if (bucket.previous > 0) bucket.previous -= 1;
      }
      // Any larger gap: the hit's window has fully expired — nothing to refund.
      return;
    }
    const prefix = `${key}::`;
    for (const [bucketKey, bucket] of this.buckets) {
      if (bucketKey.startsWith(prefix) && bucket.current > 0) {
        bucket.current -= 1;
      }
    }
  }

  private evictIfNeeded(): void {
    while (this.buckets.size > this.maxTrackedKeys) {
      // Map preserves insertion order; the first key is the oldest.
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.lastSeen > bucket.windowMs * 2) {
        this.buckets.delete(key);
      }
    }
  }

  /** Clear the cleanup timer. Alias of dispose() for ergonomic test teardown. */
  stop(): void {
    this.dispose();
  }

  dispose(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** Test/introspection helper: number of tracked keys. */
  get size(): number {
    return this.buckets.size;
  }
}
