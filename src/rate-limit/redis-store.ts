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
export class RedisRateLimitStore implements RateLimitStore {
  private readonly client: RedisLikeClient;
  private readonly keyPrefix: string;

  constructor(client: RedisLikeClient, options: RedisRateLimitStoreOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? 'esk:rl';
  }

  private bucketKey(key: string, windowIndex: number): string {
    return `${this.keyPrefix}:${key}:${windowIndex}`;
  }

  async hit(key: string, windowMs: number, now: number): Promise<HitResult> {
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
  async reset(key: string): Promise<void> {
    const now = Date.now();
    const keysToDelete: string[] = [];
    for (const windowMs of RESET_WINDOW_GUESSES) {
      const idx = Math.floor(now / windowMs);
      keysToDelete.push(this.bucketKey(key, idx), this.bucketKey(key, idx - 1));
    }
    await this.client.del(...keysToDelete);
  }
}

const RESET_WINDOW_GUESSES = [
  1_000, // 1s
  60_000, // 1m
  900_000, // 15m
  3_600_000, // 1h
  86_400_000, // 1d
];
