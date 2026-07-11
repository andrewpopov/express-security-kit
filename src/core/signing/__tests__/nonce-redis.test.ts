import { describe, it, expect } from 'vitest';
import { RedisNonceStore, RedisLikeNonceClient } from '../nonce-redis';

type SetCall = { key: string; value: string; px: 'PX'; ttlMs: number; nx: 'NX' };

/**
 * Scriptable fake of the ioredis `SET key val PX ttlMs NX` surface. `replies`
 * is consumed in order for successive `set()` calls; when it runs out, the
 * LAST reply is repeated. A reply that is an `Error` instance is thrown
 * (rejected) instead of returned, to simulate a client/connection failure.
 */
class FakeRedis implements RedisLikeNonceClient {
  public calls: SetCall[] = [];
  private replies: unknown[];

  constructor(replies: unknown[] = ['OK']) {
    this.replies = replies;
  }

  async set(
    key: string,
    value: string,
    px: 'PX',
    ttlMs: number,
    nx: 'NX',
  ): Promise<'OK' | null> {
    this.calls.push({ key, value, px, ttlMs, nx });
    const reply = this.replies.length > 1 ? this.replies.shift() : this.replies[0];
    if (reply instanceof Error) throw reply;
    return reply as 'OK' | null;
  }
}

describe('RedisNonceStore', () => {
  it('returns ok on first consume', async () => {
    const client = new FakeRedis(['OK']);
    const store = new RedisNonceStore(client);
    expect(await store.consume('scope', 'nonce-1', 5000)).toBe('ok');
  });

  it('returns replay when the underlying SET NX reports the key already exists (null)', async () => {
    const client = new FakeRedis(['OK', null]);
    const store = new RedisNonceStore(client);
    expect(await store.consume('scope', 'nonce-1', 5000)).toBe('ok');
    expect(await store.consume('scope', 'nonce-1', 5000)).toBe('replay');
  });

  it.each([['QUEUED'], [1], [undefined], [0], ['']])(
    'throws on an unexpected/ambiguous SET reply (%j) — never reinterpreted as replay',
    async (reply) => {
      const client = new FakeRedis([reply]);
      const store = new RedisNonceStore(client);
      await expect(store.consume('scope', 'nonce-1', 5000)).rejects.toThrow(
        /unexpected SET reply/,
      );
    },
  );

  it('propagates a client.set rejection (fails closed, never returns replay)', async () => {
    const client = new FakeRedis([new Error('ECONNRESET')]);
    const store = new RedisNonceStore(client);
    await expect(store.consume('scope', 'nonce-1', 5000)).rejects.toThrow('ECONNRESET');
  });

  it.each([0, -1, 1.5, NaN, Infinity, -Infinity])(
    'throws on invalid ttlMs (%s) without calling the client',
    async (ttlMs) => {
      const client = new FakeRedis(['OK']);
      const store = new RedisNonceStore(client);
      await expect(store.consume('scope', 'nonce-1', ttlMs)).rejects.toThrow(/ttlMs/);
      expect(client.calls).toHaveLength(0);
    },
  );

  it('does not collide across distinct scopes for the same nonce', async () => {
    const client = new FakeRedis(['OK', 'OK']);
    const store = new RedisNonceStore(client);
    expect(await store.consume('scopeA', 'same-nonce', 5000)).toBe('ok');
    expect(await store.consume('scopeB', 'same-nonce', 5000)).toBe('ok');
    expect(client.calls[0].key).not.toBe(client.calls[1].key);
  });

  it('calls client.set with the exact args (key, "1", "PX", ttlMs, "NX")', async () => {
    const client = new FakeRedis(['OK']);
    const store = new RedisNonceStore(client);
    await store.consume('my-scope', 'my-nonce', 12345);

    expect(client.calls).toHaveLength(1);
    const call = client.calls[0];
    expect(call.value).toBe('1');
    expect(call.px).toBe('PX');
    expect(call.ttlMs).toBe(12345);
    expect(call.nx).toBe('NX');
    // Key is namespaced + hashed, never the raw scope/nonce.
    expect(call.key).toMatch(/^esk:nonce:[0-9a-f]{64}:[0-9a-f]{64}$/);
    expect(call.key).not.toContain('my-scope');
    expect(call.key).not.toContain('my-nonce');
  });
});
