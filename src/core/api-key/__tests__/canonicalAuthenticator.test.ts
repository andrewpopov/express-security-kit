import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import type { Request } from 'express';
import {
  createCanonicalRawAuthenticator,
  type CanonicalApiKeyRecord,
} from '../canonicalAuthenticator';
import { generateApiKey } from '../issuance';
import { verifyApiKey } from '../verifyApiKey';
import type { ApiKeyAuthConfigCore } from '../types';

const PREFIX = 'app_';

function makeReq(partial: Partial<Request> = {}): Request {
  return { headers: {}, ip: '10.0.0.1', ...partial } as Request;
}

function bearer(key: string): Partial<Request> {
  return { headers: { authorization: `Bearer ${key}` } };
}

/** An in-memory "store" keyed by the public keyId, like a real DB table. */
function memoryStore(records: Record<string, CanonicalApiKeyRecord> = {}) {
  return {
    records,
    findByKeyId: async (keyId: string): Promise<CanonicalApiKeyRecord | null> =>
      records[keyId] ?? null,
  };
}

describe('createCanonicalRawAuthenticator — end-to-end regression (PKG-149 Finding 1)', () => {
  it('a key from generateApiKey authenticates end to end through the canonical adapter', async () => {
    // Mint exactly the way the README recipe does: generateApiKey stores
    // hash = hasher(secret) — the SECRET SEGMENT only.
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: { id: material.keyId, hash: material.hash },
    });

    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: store.findByKeyId,
      }),
    };

    const out = await verifyApiKey(config, makeReq(bearer(material.raw)));

    // THIS is the regression this ticket exists to fix: generateApiKey's
    // material, verified through the canonical path it was always meant to
    // pair with, must authenticate — not fail with hash_mismatch.
    expect(out).toMatchObject({ ok: true, context: { principalId: material.keyId } });
  });

  it('a second independently-minted key does not accidentally match the first (sanity: real hashing, not a stub)', async () => {
    const a = generateApiKey({ prefix: PREFIX });
    const b = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [a.keyId]: { id: a.keyId, hash: a.hash },
      [b.keyId]: { id: b.keyId, hash: b.hash },
    });
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
    });

    // b's secret against a's keyId's stored hash must not match.
    const forged = `${PREFIX}${a.keyId}.${b.raw.split('.')[1]}`;
    const out = await rawAuthenticator(forged, makeReq());
    expect(out).toEqual({ ok: false, reason: 'hash_mismatch' });
  });
});

describe('createCanonicalRawAuthenticator — rejections', () => {
  it('unknown keyId → not_found', async () => {
    const store = memoryStore({});
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
    });
    const out = await rawAuthenticator(`${PREFIX}deadbeef.some-secret-value`, makeReq());
    expect(out).toEqual({ ok: false, reason: 'not_found' });
  });

  it('wrong secret (known keyId, bad secret) → hash_mismatch', async () => {
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: { id: material.keyId, hash: material.hash },
    });
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
    });
    const out = await rawAuthenticator(`${PREFIX}${material.keyId}.wrong-secret-value`, makeReq());
    expect(out).toEqual({ ok: false, reason: 'hash_mismatch' });
  });

  it('malformed/unparseable key (no ".") is reported as malformed, distinct from "unknown keyId" (PKG-154). The client still gets the same generic 401 either way (see verifyApiKey), but the machine-readable reason now tells a structurally broken credential apart from one that simply was never issued.', async () => {
    const store = memoryStore({});
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
    });
    const out = await rawAuthenticator(`${PREFIX}not-even-a-real-key`, makeReq());
    expect(out).toEqual({ ok: false, reason: 'malformed' });
  });

  it('wrong prefix is reported as not_found, not malformed — a wrong-prefix credential was never parsed as this authenticator\'s format at all, so it is not a structural-malformation case (PKG-154 only sharpened the "prefix matched but parsing failed" branch). It also does not become bad_prefix: that reason is reserved for verifyApiKey\'s own upstream prefix check, which runs first in the real pipeline and would reject this key before this authenticator is ever invoked.', async () => {
    const store = memoryStore({});
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
    });
    const out = await rawAuthenticator('other_deadbeef.some-secret-value', makeReq());
    expect(out).toEqual({ ok: false, reason: 'not_found' });
  });

  it('a store that throws surfaces unavailable, not an auth failure', async () => {
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: async () => {
        throw new Error('DB connection refused');
      },
    });
    const out = await rawAuthenticator(`${PREFIX}deadbeef.some-secret-value`, makeReq());
    expect(out).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('requires a non-empty prefix', () => {
    expect(() =>
      createCanonicalRawAuthenticator({ prefix: '', findByKeyId: async () => null }),
    ).toThrow();
  });
});

describe('createCanonicalRawAuthenticator — through verifyApiKey (full pipeline)', () => {
  it('a store that throws → verifyApiKey reports unavailable at errorStatus (503 default), never 401', async () => {
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: async () => {
          throw new Error('DB down');
        },
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(`${PREFIX}deadbeef.some-secret-value`)));
    expect(out).toEqual({ ok: false, reason: 'unavailable', present: true, status: 503 });
  });

  it('a store that throws honors a custom errorStatus', async () => {
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      errorStatus: 500,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: async () => {
          throw new Error('DB down');
        },
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(`${PREFIX}deadbeef.some-secret-value`)));
    expect(out).toEqual({ ok: false, reason: 'unavailable', present: true, status: 500 });
  });

  it('an unknown keyId through the full pipeline → 401, not 503', async () => {
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: async () => null,
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(`${PREFIX}deadbeef.some-secret-value`)));
    expect(out).toEqual({ ok: false, reason: 'not_found', present: true, status: 401 });
  });

  it('honors a custom hasher matching the one generateApiKey was minted with', async () => {
    const hasher = vi.fn((secret: string) => `custom:${secret}`);
    const material = generateApiKey({ prefix: PREFIX, hasher });
    const store = memoryStore({
      [material.keyId]: { id: material.keyId, hash: material.hash },
    });
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: store.findByKeyId,
        hasher,
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(material.raw)));
    expect(out.ok).toBe(true);
  });

  it('expiry on the canonical record still flows through the normal pipeline', async () => {
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: {
        id: material.keyId,
        hash: material.hash,
        expiresAt: new Date(Date.now() - 1000), // already expired
      },
    });
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: store.findByKeyId,
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(material.raw)));
    expect(out).toMatchObject({ ok: false, reason: 'expired' });
  });

  it('the IP allowlist on the canonical record still flows through the normal pipeline', async () => {
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: {
        id: material.keyId,
        hash: material.hash,
        allowedIps: ['203.0.113.7'],
      },
    });
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: store.findByKeyId,
      }),
    };
    const denied = await verifyApiKey(
      config,
      makeReq({ ...bearer(material.raw), ip: '198.51.100.9' }),
    );
    expect(denied).toMatchObject({ ok: false, reason: 'ip_denied', status: 403 });

    const allowed = await verifyApiKey(
      config,
      makeReq({ ...bearer(material.raw), ip: '203.0.113.7' }),
    );
    expect(allowed.ok).toBe(true);
  });

  it('scopes on the canonical record flow into the built SecurityContext', async () => {
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: {
        id: material.keyId,
        hash: material.hash,
        scopes: ['read', 'write'],
      },
    });
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: store.findByKeyId,
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(material.raw)));
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.scopes).toEqual(['read', 'write']);
  });
});

describe('createCanonicalRawAuthenticator — key-ID existence oracle (unknown keyId must do the same work as a known one)', () => {
  it('both a known and an unknown keyId invoke the hasher (against the presented secret) and the constant-time comparison', async () => {
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: { id: material.keyId, hash: material.hash },
    });
    const hasher = vi.fn((secret: string) => createHash('sha256').update(secret).digest('hex'));
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
      hasher,
    });

    // Known keyId, wrong secret — must still hash the presented secret.
    hasher.mockClear();
    await rawAuthenticator(`${PREFIX}${material.keyId}.wrong-secret`, makeReq());
    expect(hasher).toHaveBeenCalledWith('wrong-secret');

    // Unknown keyId — must ALSO hash the presented secret (against the fixed
    // dummy hash), not short-circuit to not_found without doing the work.
    hasher.mockClear();
    await rawAuthenticator(`${PREFIX}totally-unknown-id.some-secret`, makeReq());
    expect(hasher).toHaveBeenCalledWith('some-secret');
  });

  it('a throwing hasher produces the SAME outcome for a known keyId and an unknown keyId — this is what actually pins the oracle shut (reason parity, not a timing measurement)', async () => {
    const material = generateApiKey({ prefix: PREFIX });
    const store = memoryStore({
      [material.keyId]: { id: material.keyId, hash: material.hash },
    });
    // Throws unconditionally: at authenticator-construction time (building
    // the dummy hash, which falls back to random hex instead of crashing)
    // AND on every real request.
    const throwingHasher = () => {
      throw new Error('hasher boom');
    };
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
      hasher: throwingHasher,
    });

    const knownIdOutcome = await rawAuthenticator(
      `${PREFIX}${material.keyId}.some-secret`,
      makeReq(),
    );
    const unknownIdOutcome = await rawAuthenticator(
      `${PREFIX}totally-unknown-id.some-secret`,
      makeReq(),
    );

    // Before the fix: a known id + throwing hasher -> 'unavailable' (the
    // hasher call happened and threw), while an unknown id short-circuited
    // to 'not_found' BEFORE ever calling the hasher — two different,
    // reliably distinguishable outcomes with no timing measurement needed.
    // After the fix: both call the hasher unconditionally, so both land on
    // the SAME reason.
    expect(knownIdOutcome).toEqual({ ok: false, reason: 'unavailable' });
    expect(unknownIdOutcome).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('a throwing hasher does not authenticate and is never mistaken for hash_mismatch (an infra fault is not an auth decision)', async () => {
    const store = memoryStore({});
    const rawAuthenticator = createCanonicalRawAuthenticator<Request>({
      prefix: PREFIX,
      findByKeyId: store.findByKeyId,
      hasher: () => { throw new Error('hasher boom'); },
    });
    const out = await rawAuthenticator(`${PREFIX}deadbeef.some-secret`, makeReq());
    expect(out).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('through the full pipeline, a throwing hasher surfaces unavailable at errorStatus (503 default), never 401, for an unknown keyId too', async () => {
    const config: ApiKeyAuthConfigCore<Request> = {
      prefix: PREFIX,
      rawAuthenticator: createCanonicalRawAuthenticator<Request>({
        prefix: PREFIX,
        findByKeyId: async () => null, // unknown keyId
        hasher: () => { throw new Error('hasher boom'); },
      }),
    };
    const out = await verifyApiKey(config, makeReq(bearer(`${PREFIX}deadbeef.some-secret`)));
    expect(out).toEqual({ ok: false, reason: 'unavailable', present: true, status: 503 });
  });
});
