import { describe, it, expect, afterEach } from 'vitest';
import { RedisRateLimitStore, RedisLikeClient } from '../redis-store';
import { MemoryRateLimitStore } from '../store';

/**
 * Hand-written in-memory fake of the ioredis surface the store uses, WITH
 * `eval` implemented so the atomic hit path is exercised. `eval` interprets
 * OUR hit script directly (INCR the map; arm an expiry marker the first time
 * a key has none; GET the previous bucket) rather than a real Lua VM, so the
 * fake stays simple while still proving the atomic path's behavior and call
 * shape.
 */
class FakeRedis implements RedisLikeClient {
  private data = new Map<string, number>();
  private ttlArmed = new Set<string>();
  public pexpireCalls: Array<{ key: string; ms: number }> = [];
  public evalCalls: Array<{ script: string; numKeys: number; args: (string | number)[] }> = [];

  async incr(key: string): Promise<number> {
    const next = (this.data.get(key) ?? 0) + 1;
    this.data.set(key, next);
    return next;
  }
  async decr(key: string): Promise<number> {
    const next = (this.data.get(key) ?? 0) - 1;
    this.data.set(key, next);
    return next;
  }
  async pexpire(key: string, ms: number): Promise<number> {
    this.pexpireCalls.push({ key, ms });
    this.ttlArmed.add(key);
    return 1;
  }
  async get(key: string): Promise<string | null> {
    const v = this.data.get(key);
    return v === undefined ? null : String(v);
  }
  async del(...keys: string[]): Promise<number> {
    let n = 0;
    for (const k of keys) {
      if (this.data.delete(k)) n++;
      this.ttlArmed.delete(k);
    }
    return n;
  }

  /**
   * Interprets the store's scripts. HIT_SCRIPT: INCR KEYS[1]; arm TTL if unset;
   * GET KEYS[2]. DECREMENT_SCRIPT: conditional DECR KEYS[1] iff present and > 0.
   */
  async eval(
    script: string,
    numKeys: number,
    ...args: (string | number)[]
  ): Promise<unknown> {
    this.evalCalls.push({ script, numKeys, args });
    if (script.includes('DECR')) {
      const [bucketKey] = args as [string];
      const v = this.data.get(bucketKey);
      if (v !== undefined && v > 0) {
        this.data.set(bucketKey, v - 1);
        return v - 1;
      }
      return v ?? 0;
    }
    const [currentKey, previousKey, ttlArg] = args as [string, string, string];
    const current = (this.data.get(currentKey) ?? 0) + 1;
    this.data.set(currentKey, current);
    if (!this.ttlArmed.has(currentKey)) {
      this.pexpireCalls.push({ key: currentKey, ms: Number(ttlArg) });
      this.ttlArmed.add(currentKey);
    }
    const prev = this.data.get(previousKey);
    // Mirror the script: heal a leaked PREVIOUS key (present but no TTL) the one
    // time it is read, so an earlier-window leak can't live forever.
    if (prev !== undefined && !this.ttlArmed.has(previousKey)) {
      this.pexpireCalls.push({ key: previousKey, ms: Number(ttlArg) });
      this.ttlArmed.add(previousKey);
    }
    return [current, prev === undefined ? '0' : String(prev)];
  }

  /** Test helper: seed a key as if leaked by a crash — data present, no TTL armed. */
  seedLeaked(key: string, count: number): void {
    this.data.set(key, count);
    this.ttlArmed.delete(key);
  }

  hasTtl(key: string): boolean {
    return this.ttlArmed.has(key);
  }
}

/** A minimal fake WITHOUT `eval`, to exercise the documented non-atomic fallback. */
class NoEvalFakeRedis implements RedisLikeClient {
  private data = new Map<string, number>();
  public pexpireCalls: Array<{ key: string; ms: number }> = [];

  async incr(key: string): Promise<number> {
    const next = (this.data.get(key) ?? 0) + 1;
    this.data.set(key, next);
    return next;
  }
  async decr(key: string): Promise<number> {
    const next = (this.data.get(key) ?? 0) - 1;
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

describe('RedisRateLimitStore — atomic eval path', () => {
  it('counts hits and arms a TTL only on the first hit', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    const a = await store.hit('k', 1000, 5000);
    expect(a).toEqual({ current: 1, previous: 0, resetAt: 6000 });
    expect(redis.evalCalls).toHaveLength(1);
    const b = await store.hit('k', 1000, 5500);
    expect(b.current).toBe(2);
    expect(redis.pexpireCalls).toHaveLength(1);
    expect(redis.pexpireCalls[0].ms).toBe(2000);
  });

  it('calls eval with exactly (script, 2, currentKey, previousKey, ttl)', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis, { keyPrefix: 'esk:rl' });
    await store.hit('k', 1000, 5000);
    expect(redis.evalCalls).toHaveLength(1);
    const call = redis.evalCalls[0];
    expect(typeof call.script).toBe('string');
    expect(call.numKeys).toBe(2);
    expect(call.args).toEqual(['esk:rl:k:1000:5', 'esk:rl:k:1000:4', '2000']);
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

  it('heals a leaked (no-TTL) key on the next hit (PTTL < 0 re-arms)', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    // Simulate a key leaked by a crash (or the old non-atomic path): data
    // present, TTL never armed.
    redis.seedLeaked('esk:rl:k:1000:5', 3);
    expect(redis.hasTtl('esk:rl:k:1000:5')).toBe(false);
    const hit = await store.hit('k', 1000, 5000);
    expect(hit.current).toBe(4);
    expect(redis.hasTtl('esk:rl:k:1000:5')).toBe(true);
  });

  it('heals a leaked PREVIOUS-window key when it is read as the sliding estimate', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    // A counter leaked in window 4 (present, no TTL). The next hit lands in
    // window 5 and reads window 4 as "previous" — that read must re-arm its TTL.
    redis.seedLeaked('esk:rl:k:1000:4', 7);
    expect(redis.hasTtl('esk:rl:k:1000:4')).toBe(false);
    const hit = await store.hit('k', 1000, 5000);
    expect(hit.previous).toBe(7);
    expect(redis.hasTtl('esk:rl:k:1000:4')).toBe(true);
  });

  it('throws on a malformed (non-array) eval result', async () => {
    const badRedis: RedisLikeClient = {
      incr: async () => 1,
      pexpire: async () => 1,
      get: async () => null,
      del: async () => 0,
      eval: async () => 'not-an-array',
    };
    const store = new RedisRateLimitStore(badRedis);
    await expect(store.hit('k', 1000, 5000)).rejects.toThrow(/malformed/i);
  });

  it('throws on a non-integer/negative value inside an otherwise array-shaped eval result', async () => {
    const badRedis: RedisLikeClient = {
      incr: async () => 1,
      pexpire: async () => 1,
      get: async () => null,
      del: async () => 0,
      eval: async () => [1.5, -1],
    };
    const store = new RedisRateLimitStore(badRedis);
    await expect(store.hit('k', 1000, 5000)).rejects.toThrow(/malformed/i);
  });

  it('throws on a too-short array eval result', async () => {
    const badRedis: RedisLikeClient = {
      incr: async () => 1,
      pexpire: async () => 1,
      get: async () => null,
      del: async () => 0,
      eval: async () => [1],
    };
    const store = new RedisRateLimitStore(badRedis);
    await expect(store.hit('k', 1000, 5000)).rejects.toThrow(/malformed/i);
  });
});

describe('RedisRateLimitStore — eval-less fallback (documented non-atomic path)', () => {
  it('falls back to INCR/PEXPIRE/GET when the client has no eval', async () => {
    const redis = new NoEvalFakeRedis();
    const store = new RedisRateLimitStore(redis);
    const a = await store.hit('k', 1000, 5000);
    expect(a).toEqual({ current: 1, previous: 0, resetAt: 6000 });
    const b = await store.hit('k', 1000, 5500);
    expect(b.current).toBe(2);
    expect(redis.pexpireCalls.every((c) => c.ms === 2000)).toBe(true);
  });

  it('rolls previous window into the sliding estimate (fallback path)', async () => {
    const store = new RedisRateLimitStore(new NoEvalFakeRedis());
    await store.hit('k', 1000, 5000);
    await store.hit('k', 1000, 5500);
    const next = await store.hit('k', 1000, 6000);
    expect(next.previous).toBe(2);
    expect(next.current).toBe(1);
    expect(next.resetAt).toBe(7000);
  });
});

describe('RedisRateLimitStore — reset', () => {
  it('reset(key) with no windowMs deletes buckets for the key (window-size-guess fallback)', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    await store.hit('k', 1000, Math.floor(Date.now() / 1000) * 1000);
    await store.reset('k');
    // A subsequent hit in the same 1s window starts fresh.
    const after = await store.hit('k', 1000, Math.floor(Date.now() / 1000) * 1000);
    expect(after.current).toBe(1);
  });

  it('reset(key, windowMs) clears ONLY the exact current+previous buckets for that window', async () => {
    // reset(key, windowMs) computes its window index from the REAL wall
    // clock (like the original no-windowMs reset did), so `now` here must
    // track Date.now() rather than a fixed simulated timestamp.
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    const now1000 = Math.floor(Date.now() / 1000) * 1000;
    const now5000 = Math.floor(Date.now() / 5000) * 5000;
    await store.hit('k', 1000, now1000);
    await store.hit('k', 5000, now5000); // different windowMs (untouched)

    await store.reset('k', 1000);

    const after1000 = await store.hit('k', 1000, now1000);
    expect(after1000.current).toBe(1); // cleared by the precise reset
    const after5000 = await store.hit('k', 5000, now5000);
    expect(after5000.current).toBe(2); // NOT touched by the windowMs-scoped reset
  });

  it('honors a custom keyPrefix', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis, { keyPrefix: 'myapp' });
    await store.hit('k', 1000, 5000);
    expect(redis.pexpireCalls[0].key.startsWith('myapp:k:')).toBe(true);
  });
});

describe('RedisRateLimitStore — decrement', () => {
  it('refunds the exact current-window bucket (atomic eval path)', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    await store.hit('k', 1000, 5000); // current = 1
    await store.hit('k', 1000, 5000); // current = 2
    await store.decrement('k', 1000, 5000);
    const after = await store.hit('k', 1000, 5000); // 2 - 1 + 1
    expect(after.current).toBe(2);
  });

  it('floors at 0: never creates a phantom key or goes negative (eval path)', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    // Decrement a bucket that was never hit → no-op (no phantom -1).
    await store.decrement('missing', 1000, 5000);
    const after = await store.hit('missing', 1000, 5000);
    expect(after.current).toBe(1); // fresh, not 0-from-a-phantom
  });

  it('floors at 0 across repeated decrements (eval path)', async () => {
    const redis = new FakeRedis();
    const store = new RedisRateLimitStore(redis);
    await store.hit('k', 1000, 5000); // current = 1
    await store.decrement('k', 1000, 5000);
    await store.decrement('k', 1000, 5000); // already 0 → no-op
    const after = await store.hit('k', 1000, 5000);
    expect(after.current).toBe(1);
  });

  it('refunds via the non-atomic fallback when the client has no eval', async () => {
    const redis = new NoEvalFakeRedis();
    const store = new RedisRateLimitStore(redis);
    await store.hit('k', 1000, 5000);
    await store.hit('k', 1000, 5000); // current = 2
    await store.decrement('k', 1000, 5000);
    const after = await store.hit('k', 1000, 5000); // 2 - 1 + 1
    expect(after.current).toBe(2);
  });

  it('fallback does not DECR a missing/zero key (no negative)', async () => {
    const redis = new NoEvalFakeRedis();
    const store = new RedisRateLimitStore(redis);
    await store.decrement('missing', 1000, 5000); // no-op
    const after = await store.hit('missing', 1000, 5000);
    expect(after.current).toBe(1);
  });
});

describe('RedisRateLimitStore — parity with MemoryRateLimitStore', () => {
  it('produces identical current/previous/resetAt to MemoryRateLimitStore', async () => {
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
