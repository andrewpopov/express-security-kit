import { describe, it, expect, afterEach } from 'vitest';
import { RedisRateLimitStore, RedisLikeClient } from '../redis-store';
import { MemoryRateLimitStore } from '../store';

/**
 * Hand-written in-memory fake of the ioredis surface the store uses. Bucket
 * keys already encode the window index, so real TTL expiry is not needed for
 * count correctness — we track it only to prove pexpire is called.
 */
class FakeRedis implements RedisLikeClient {
  private data = new Map<string, number>();
  public pexpireCalls: Array<{ key: string; ms: number }> = [];

  async incr(key: string): Promise<number> {
    const next = (this.data.get(key) ?? 0) + 1;
    this.data.set(key, next);
    return next;
  }
  async pexpire(key: string, ms: number): Promise<number> {
    this.pexpireCalls.push({ key, ms });
    return 1;
  }
  async get(key: string): Promise<string | null> {
    const v = this.data.get(key);
    return v === undefined ? null : String(v);
  }
  async del(...keys: string[]): Promise<number> {
    let n = 0;
    for (const k of keys) if (this.data.delete(k)) n++;
    return n;
  }
}

const memStores: MemoryRateLimitStore[] = [];
afterEach(() => {
  while (memStores.length) memStores.pop()!.stop();
});

describe('RedisRateLimitStore', () => {
  it('counts hits and sets a 2-window TTL', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    const a = await store.hit('k', 1000, 5000);
    expect(a).toEqual({ current: 1, previous: 0, resetAt: 6000 });
    const b = await store.hit('k', 1000, 5500);
    expect(b.current).toBe(2);
    expect(redis.pexpireCalls.every((c) => c.ms === 2000)).toBe(true);
  });

  it('rolls previous window into the sliding estimate', async () => {
    const store = new RedisRateLimitStore(new FakeRedis());
    await store.hit('k', 1000, 5000);
    await store.hit('k', 1000, 5500); // window index 5 -> count 2
    const next = await store.hit('k', 1000, 6000); // window index 6
    expect(next.previous).toBe(2);
    expect(next.current).toBe(1);
    expect(next.resetAt).toBe(7000);
  });

  it('reset() deletes buckets for the key', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    await store.hit('k', 1000, Math.floor(Date.now() / 1000) * 1000);
    await store.reset('k');
    // A subsequent hit in the same 1s window starts fresh.
    const after = await store.hit('k', 1000, Math.floor(Date.now() / 1000) * 1000);
    expect(after.current).toBe(1);
  });

  it('honors a custom keyPrefix', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis, { keyPrefix: 'myapp' });
    await store.hit('k', 1000, 5000);
    expect(redis.pexpireCalls[0].key.startsWith('myapp:k:')).toBe(true);
  });

  it('produces identical current/previous to MemoryRateLimitStore', async () => {
    const redis = new RedisRateLimitStore(new FakeRedis());
    const mem = new MemoryRateLimitStore();
    memStores.push(mem);

    const windowMs = 1000;
    // A sequence that spans several windows including a skipped one.
    const times = [5000, 5100, 5900, 6000, 6500, 8000, 8000, 9000];
    for (const t of times) {
      const r = await redis.hit('same', windowMs, t);
      const m = await mem.hit('same', windowMs, t);
      expect({ current: r.current, previous: r.previous, resetAt: r.resetAt }).toEqual({
        current: m.current,
        previous: m.previous,
        resetAt: m.resetAt,
      });
    }
  });
});
