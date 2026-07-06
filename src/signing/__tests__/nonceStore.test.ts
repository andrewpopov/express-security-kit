import { describe, it, expect, afterEach } from 'vitest';
import { MemoryNonceStore } from '../nonceStore';

const stores: MemoryNonceStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryNonceStore>) {
  const s = new MemoryNonceStore(...args);
  stores.push(s);
  return s;
}
afterEach(() => {
  while (stores.length) stores.pop()!.stop();
});

describe('MemoryNonceStore', () => {
  it('returns ok first, replay on second use within TTL', async () => {
    const store = makeStore({ now: () => 1000 });
    expect(await store.consume('s', 'nonce-1', 5000)).toBe('ok');
    expect(await store.consume('s', 'nonce-1', 5000)).toBe('replay');
  });

  it('isolates nonces by scope', async () => {
    const store = makeStore({ now: () => 1000 });
    expect(await store.consume('scopeA', 'nonce-1', 5000)).toBe('ok');
    // Same nonce, different scope → not a replay.
    expect(await store.consume('scopeB', 'nonce-1', 5000)).toBe('ok');
  });

  it('allows reuse after the TTL expires', async () => {
    let now = 1000;
    const store = makeStore({ now: () => now });
    expect(await store.consume('s', 'n', 5000)).toBe('ok'); // expires at 6000
    now = 6001;
    expect(await store.consume('s', 'n', 5000)).toBe('ok'); // expired → fresh
  });

  it('THROWS instead of evicting a live nonce past the cap (fail closed)', async () => {
    const store = makeStore({ maxTrackedNonces: 2, now: () => 1000 });
    await store.consume('s', 'a', 5000); // live until 6000
    await store.consume('s', 'b', 5000); // live until 6000
    // 'c' would push over cap; all existing are live → must throw, NOT evict.
    await expect(store.consume('s', 'c', 5000)).rejects.toThrow(/capacity exceeded/);
    // The still-live 'a' was NOT evicted, so replaying it is caught.
    expect(await store.consume('s', 'a', 5000)).toBe('replay');
  });

  it('prunes EXPIRED entries to free capacity for new nonces', async () => {
    let now = 1000;
    const store = makeStore({ maxTrackedNonces: 2, now: () => now });
    await store.consume('s', 'a', 5000); // expires at 6000
    await store.consume('s', 'b', 5000); // expires at 6000
    now = 6001; // both 'a' and 'b' now expired
    // 'c' pushes over cap, but pruning expired frees room → 'ok', no throw.
    expect(await store.consume('s', 'c', 5000)).toBe('ok');
    expect(store.size).toBe(1);
  });

  it('constructor throws on maxTrackedNonces <= 0', () => {
    expect(() => new MemoryNonceStore({ maxTrackedNonces: 0 })).toThrow();
    expect(() => new MemoryNonceStore({ maxTrackedNonces: -5 })).toThrow();
  });

  it('stop() is idempotent', () => {
    const store = new MemoryNonceStore();
    store.stop();
    store.stop();
    expect(store.size).toBe(0);
  });
});
