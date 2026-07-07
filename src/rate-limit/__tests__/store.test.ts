import { describe, it, expect, afterEach } from 'vitest';
import { MemoryRateLimitStore } from '../store';

const stores: MemoryRateLimitStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryRateLimitStore>) {
  const s = new MemoryRateLimitStore(...args);
  stores.push(s);
  return s;
}

afterEach(() => {
  while (stores.length) stores.pop()!.stop();
});

describe('MemoryRateLimitStore', () => {
  it('counts hits within the same window and reports resetAt', async () => {
    const store = makeStore();
    const windowMs = 1000;
    const now = 5000; // windowStart = 5000, resetAt = 6000
    const a = await store.hit('k', windowMs, now);
    expect(a).toEqual({ current: 1, previous: 0, resetAt: 6000 });
    const b = await store.hit('k', windowMs, now + 100);
    expect(b).toEqual({ current: 2, previous: 0, resetAt: 6000 });
  });

  it('rolls current into previous on the next window', async () => {
    const store = makeStore();
    const windowMs = 1000;
    await store.hit('k', windowMs, 5000);
    await store.hit('k', windowMs, 5500); // current window count = 2
    const next = await store.hit('k', windowMs, 6000); // new window
    expect(next.previous).toBe(2);
    expect(next.current).toBe(1);
    expect(next.resetAt).toBe(7000);
  });

  it('zeroes previous when a full window is skipped', async () => {
    const store = makeStore();
    const windowMs = 1000;
    await store.hit('k', windowMs, 5000);
    const jumped = await store.hit('k', windowMs, 8000); // 3 windows later
    expect(jumped.previous).toBe(0);
    expect(jumped.current).toBe(1);
  });

  it('keeps independent buckets per (key, windowMs) on a shared store', async () => {
    const store = makeStore();
    const now = 5000;
    // Same key, two different window lengths sharing ONE store.
    const a1 = await store.hit('same', 1000, now);
    const b1 = await store.hit('same', 60_000, now);
    expect(a1.current).toBe(1);
    expect(b1.current).toBe(1);
    // Incrementing one must not reset or bleed into the other.
    const a2 = await store.hit('same', 1000, now);
    const b2 = await store.hit('same', 60_000, now);
    expect(a2.current).toBe(2);
    expect(b2.current).toBe(2);
    // Distinct resetAt values confirm they are genuinely separate windows.
    expect(a2.resetAt).not.toBe(b2.resetAt);
    expect(store.size).toBe(2);
  });

  it('reset() clears a key', async () => {
    const store = makeStore();
    await store.hit('k', 1000, 5000);
    await store.reset('k');
    const after = await store.hit('k', 1000, 5000);
    expect(after.current).toBe(1);
  });

  it('evicts oldest keys past MAX_TRACKED_KEYS', async () => {
    const store = makeStore({ maxTrackedKeys: 3 });
    await store.hit('a', 1000, 1000);
    await store.hit('b', 1000, 1000);
    await store.hit('c', 1000, 1000);
    expect(store.size).toBe(3);
    await store.hit('d', 1000, 1000); // evicts 'a'
    expect(store.size).toBe(3);
    // 'a' was evicted, so it starts fresh
    const a = await store.hit('a', 1000, 1000);
    expect(a.current).toBe(1);
  });

  it('touching a key refreshes its eviction recency', async () => {
    const store = makeStore({ maxTrackedKeys: 2 });
    await store.hit('a', 1000, 1000);
    await store.hit('b', 1000, 1000);
    await store.hit('a', 1000, 1000); // 'a' becomes most-recent
    await store.hit('c', 1000, 1000); // should evict 'b', not 'a'
    const a = await store.hit('a', 1000, 1000);
    expect(a.current).toBeGreaterThan(1); // 'a' survived
  });

  it('stop() is idempotent and safe', () => {
    const store = new MemoryRateLimitStore();
    store.stop();
    store.stop();
    expect(store.size).toBe(0);
  });

  it('reset(key, windowMs) clears only that window bucket', async () => {
    const store = makeStore();
    await store.hit('k', 1000, 5000);
    await store.hit('k', 60_000, 5000);
    await store.reset('k', 1000);
    const after1000 = await store.hit('k', 1000, 5000);
    expect(after1000.current).toBe(1); // cleared
    const after60000 = await store.hit('k', 60_000, 5000);
    expect(after60000.current).toBe(2); // untouched
  });
});

describe('MemoryRateLimitStore — concurrency', () => {
  it('fans out N parallel hits on the same key with no lost updates', async () => {
    const store = makeStore();
    const N = 200;
    const results = await Promise.all(
      Array.from({ length: N }, () => store.hit('concurrent-key', 1000, 5000)),
    );
    const currents = results.map((r) => r.current).sort((a, b) => a - b);
    // Every increment landed exactly once: N unique sequential counts 1..N.
    expect(currents).toEqual(Array.from({ length: N }, (_, i) => i + 1));
  });

  it('a flood of distinct keys past maxTrackedKeys drops oldest and keeps size bounded', async () => {
    const store = makeStore({ maxTrackedKeys: 50 });
    const N = 500;
    await Promise.all(
      Array.from({ length: N }, (_, i) => store.hit(`key-${i}`, 1000, 1000)),
    );
    expect(store.size).toBeLessThanOrEqual(50);
  });
});
