import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Redis from 'ioredis';
import { RedisRateLimitStore } from '../redis-store';
import { createRateLimiter } from '../createRateLimiter';

/**
 * Real-Redis integration test. NO-OPs (via `describe.skipIf`) unless
 * `ESK_REDIS_URL` is set, so it never runs locally or in the normal CI `test`
 * job — only in the separate, non-required `redis-integration` CI job that
 * spins up a `services: redis` container.
 */
const REDIS_URL = process.env.ESK_REDIS_URL;

describe.skipIf(!REDIS_URL)('RedisRateLimitStore — real ioredis integration', () => {
  let client: Redis;

  beforeAll(() => {
    client = new Redis(REDIS_URL as string);
  });

  afterAll(async () => {
    await client.quit();
  });

  it('INCR/PEXPIRE atomic path sets a TTL on the bucket key', async () => {
    const keyPrefix = `esk:it:atomic:${Date.now()}`;
    const store = new RedisRateLimitStore(client, { keyPrefix });
    const now = Date.now();
    const hit = await store.hit('atomic-key', 1000, now);
    expect(hit.current).toBe(1);

    // Reconstruct the exact bucket key the store used and confirm a TTL was armed.
    const windowIndex = Math.floor(now / 1000);
    const bucketKey = `${keyPrefix}:atomic-key:1000:${windowIndex}`;
    const pttl = await client.pttl(bucketKey);
    expect(pttl).toBeGreaterThan(0);
  });

  it('sliding estimate rolls over a real window boundary', async () => {
    const keyPrefix = `esk:it:sliding:${Date.now()}`;
    const store = new RedisRateLimitStore(client, { keyPrefix });
    const windowMs = 1000;
    const base = Math.floor(Date.now() / windowMs) * windowMs;

    await store.hit('roll-key', windowMs, base);
    await store.hit('roll-key', windowMs, base + 100); // same window -> current 2
    const next = await store.hit('roll-key', windowMs, base + windowMs); // next window
    expect(next.previous).toBe(2);
    expect(next.current).toBe(1);
  });

  it('reset(key, windowMs) clears the exact current+previous buckets', async () => {
    const keyPrefix = `esk:it:reset:${Date.now()}`;
    const store = new RedisRateLimitStore(client, { keyPrefix });
    const windowMs = 1000;
    const now = Math.floor(Date.now() / windowMs) * windowMs;
    await store.hit('reset-key', windowMs, now);
    await store.reset('reset-key', windowMs);
    const after = await store.hit('reset-key', windowMs, now);
    expect(after.current).toBe(1);
  });

  it('fails OPEN through createRateLimiter when the Redis client errors mid-hit', async () => {
    // A client whose eval (and fallback incr) always rejects, simulating a
    // Redis outage/error mid-request. The FAIL-OPEN behavior belongs to
    // createRateLimiter, not the store, so drive it through the limiter.
    const erroringClient = {
      incr: () => Promise.reject(new Error('redis down')),
      pexpire: () => Promise.reject(new Error('redis down')),
      get: () => Promise.reject(new Error('redis down')),
      del: () => Promise.reject(new Error('redis down')),
      eval: () => Promise.reject(new Error('redis down')),
    };
    const store = new RedisRateLimitStore(erroringClient as unknown as ConstructorParameters<typeof RedisRateLimitStore>[0]);
    const warnings: unknown[] = [];
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 1,
      store,
      logger: { warn: (msg, meta) => warnings.push({ msg, meta }) },
    });

    let nextCalled = false;
    let statusCode: number | undefined;
    const res: any = {
      setHeader: () => undefined,
      status(code: number) {
        statusCode = code;
        return res;
      },
      json() {
        return res;
      },
    };
    await new Promise<void>((resolve) => {
      mw({ headers: {}, ip: '1.2.3.4' } as any, res, () => {
        nextCalled = true;
        resolve();
      });
    });

    expect(nextCalled).toBe(true);
    expect(statusCode).toBeUndefined();
    expect(warnings.length).toBeGreaterThan(0);
  });
});
