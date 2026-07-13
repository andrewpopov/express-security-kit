import { describe, it, expect, vi } from 'vitest';
import {
  generateApiKey,
  parseApiKey,
  maskApiKey,
  rotateApiKey,
  createThrottledTouchLastUsed,
  type ApiKeyStore,
  type ApiKeyStoreRecord,
} from '../issuance';
import { sha256Hasher } from '../hashers';

describe('generateApiKey / parseApiKey', () => {
  it('produces a raw key that parses back to the same keyId', () => {
    const material = generateApiKey({ prefix: 'ssk_' });
    expect(material.raw.startsWith('ssk_')).toBe(true);
    const parsed = parseApiKey(material.raw, 'ssk_');
    expect(parsed).not.toBeNull();
    expect(parsed?.keyId).toBe(material.keyId);
  });

  it('the hash verifies against the parsed secret', () => {
    const material = generateApiKey({ prefix: 'ssk_' });
    const parsed = parseApiKey(material.raw, 'ssk_')!;
    expect(sha256Hasher()(parsed.secret)).toBe(material.hash);
  });

  it('supports a custom hasher (reuses the kit hashing seam)', () => {
    const hasher = vi.fn((s: string) => `custom:${s}`);
    const material = generateApiKey({ prefix: 'ssk_', hasher });
    expect(hasher).toHaveBeenCalled();
    expect(material.hash).toBe(`custom:${parseApiKey(material.raw, 'ssk_')!.secret}`);
  });

  it('requires a non-empty prefix', () => {
    expect(() => generateApiKey({ prefix: '' })).toThrow();
  });

  it('parseApiKey never throws on malformed input and returns null', () => {
    expect(parseApiKey('not-even-close', 'ssk_')).toBeNull();
    expect(parseApiKey('ssk_', 'ssk_')).toBeNull(); // no '.'
    expect(parseApiKey('ssk_.secret', 'ssk_')).toBeNull(); // empty keyId
    expect(parseApiKey('ssk_keyid.', 'ssk_')).toBeNull(); // empty secret
    expect(parseApiKey('wrongprefix_keyid.secret', 'ssk_')).toBeNull();
    // @ts-expect-error deliberately wrong type to prove no throw
    expect(parseApiKey(undefined, 'ssk_')).toBeNull();
  });

  it('maskApiKey never reveals the secret', () => {
    const material = generateApiKey({ prefix: 'ssk_' });
    const masked = maskApiKey(material);
    expect(masked).toBe(`ssk_${material.keyId}...${material.last4}`);
    const parsed = parseApiKey(material.raw, 'ssk_')!;
    expect(masked).not.toContain(parsed.secret);
  });

  it('generates unique keyId/secret across calls', () => {
    const a = generateApiKey({ prefix: 'ssk_' });
    const b = generateApiKey({ prefix: 'ssk_' });
    expect(a.keyId).not.toBe(b.keyId);
    expect(a.raw).not.toBe(b.raw);
  });
});

// In-memory ApiKeyStore fake for testing rotate/touch.
function createFakeStore(): ApiKeyStore & { records: Map<string, ApiKeyStoreRecord> } {
  const records = new Map<string, ApiKeyStoreRecord>();
  return {
    records,
    async findByKeyId(keyId) {
      return records.get(keyId) ?? null;
    },
    async insert(record) {
      records.set(record.keyId, { ...record });
    },
    async revoke(keyId) {
      const existing = records.get(keyId);
      if (existing) existing.revoked = true;
    },
    async touchLastUsed() {
      // no-op for these tests
    },
  };
}

describe('rotateApiKey', () => {
  it('old key becomes invalid, new key becomes valid', async () => {
    const store = createFakeStore();
    await store.insert({ keyId: 'old-1', hash: 'oldhash' });

    const material = await rotateApiKey(store, 'old-1', { prefix: 'ssk_' });

    const oldRecord = await store.findByKeyId('old-1');
    const newRecord = await store.findByKeyId(material.keyId);
    expect(oldRecord?.revoked).toBe(true);
    expect(newRecord?.revoked).toBeFalsy();
    expect(newRecord?.hash).toBe(material.hash);
  });

  it('without store.transaction, inserts the new key before revoking the old one (no window where NEITHER works)', async () => {
    const store = createFakeStore();
    await store.insert({ keyId: 'old-1', hash: 'oldhash' });

    const insertSpy = vi.spyOn(store, 'insert');
    const revokeSpy = vi.spyOn(store, 'revoke');

    await rotateApiKey(store, 'old-1', { prefix: 'ssk_' });

    expect(insertSpy.mock.invocationCallOrder[0]).toBeLessThan(
      revokeSpy.mock.invocationCallOrder[0],
    );
  });

  it('with store.transaction, both operations run inside the transaction callback atomically', async () => {
    const store = createFakeStore();
    await store.insert({ keyId: 'old-1', hash: 'oldhash' });

    // Simulate a real transaction: draft state committed only if the
    // callback resolves without throwing, so an outside observer never sees
    // a partial state (neither "old revoked but new missing" nor vice
    // versa).
    let committedState: Map<string, ApiKeyStoreRecord> | null = null;
    store.transaction = async (fn) => {
      const draft = new Map(store.records);
      const tx = {
        insert: async (record: ApiKeyStoreRecord) => {
          draft.set(record.keyId, { ...record });
        },
        revoke: async (keyId: string) => {
          const existing = draft.get(keyId);
          if (existing) draft.set(keyId, { ...existing, revoked: true });
        },
      };
      const result = await fn(tx);
      // Commit: only now does the outside world see the new state.
      for (const [k, v] of draft) store.records.set(k, v);
      committedState = draft;
      return result;
    };

    const beforeOld = await store.findByKeyId('old-1');
    expect(beforeOld?.revoked).toBeFalsy();

    const material = await rotateApiKey(store, 'old-1', { prefix: 'ssk_' });

    expect(committedState).not.toBeNull();
    const oldRecord = await store.findByKeyId('old-1');
    const newRecord = await store.findByKeyId(material.keyId);
    expect(oldRecord?.revoked).toBe(true);
    expect(newRecord?.revoked).toBeFalsy();
  });
});

describe('createThrottledTouchLastUsed', () => {
  it('throttles: N calls within the window produce exactly 1 write', async () => {
    const touchLastUsed = vi.fn(async () => {});
    let clock = 1000;
    const touch = createThrottledTouchLastUsed(
      { touchLastUsed },
      { minIntervalMs: 60_000, now: () => clock },
    );

    touch('key-1');
    clock += 100;
    touch('key-1');
    clock += 100;
    touch('key-1');
    clock += 100;
    touch('key-1');

    await Promise.resolve();
    expect(touchLastUsed).toHaveBeenCalledTimes(1);
  });

  it('writes again once the window elapses', async () => {
    const touchLastUsed = vi.fn(async () => {});
    let clock = 1000;
    const touch = createThrottledTouchLastUsed(
      { touchLastUsed },
      { minIntervalMs: 1000, now: () => clock },
    );

    touch('key-1');
    clock += 1500;
    touch('key-1');

    await Promise.resolve();
    expect(touchLastUsed).toHaveBeenCalledTimes(2);
  });

  it('throttles independently per keyId', async () => {
    const touchLastUsed = vi.fn(async () => {});
    const clock = 1000;
    const touch = createThrottledTouchLastUsed(
      { touchLastUsed },
      { minIntervalMs: 60_000, now: () => clock },
    );

    touch('key-1');
    touch('key-2');

    await Promise.resolve();
    expect(touchLastUsed).toHaveBeenCalledTimes(2);
  });

  it('never throws when the store rejects; routes the failure to onError instead of swallowing it silently', async () => {
    const touchLastUsed = vi.fn(async () => {
      throw new Error('write failed');
    });
    const onError = vi.fn();
    const touch = createThrottledTouchLastUsed({ touchLastUsed }, { onError });

    expect(() => touch('key-1')).not.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(onError).toHaveBeenCalledWith('key-1', expect.any(Error));
  });
});

// Passing the RAW key to maskApiKey is the obvious mistake. Before this guard it
// returned "undefinedundefined...undefined" — garbage that still LOOKS like a
// mask, so a consumer would store or display it and never notice.
describe('maskApiKey rejects input that is not ApiKeyMaterial', () => {
  it('throws when handed the raw key string instead of the material', () => {
    const material = generateApiKey({ prefix: 'smh_' });
    expect(() => maskApiKey(material.raw as unknown as typeof material)).toThrow(TypeError);
  });

  it('throws on null/undefined/partial material rather than emitting garbage', () => {
    expect(() => maskApiKey(null as never)).toThrow(TypeError);
    expect(() => maskApiKey(undefined as never)).toThrow(TypeError);
    expect(() => maskApiKey({ prefix: 'x_' } as never)).toThrow(TypeError);
  });
});
