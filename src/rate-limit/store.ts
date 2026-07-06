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

  async reset(key: string): Promise<void> {
    // Buckets are namespaced as `${key}::${windowMs}`, so clear every window
    // bucket belonging to this key.
    const prefix = `${key}::`;
    for (const bucketKey of this.buckets.keys()) {
      if (bucketKey.startsWith(prefix)) {
        this.buckets.delete(bucketKey);
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
