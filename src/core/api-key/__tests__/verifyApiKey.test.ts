import { describe, it, expect, vi } from 'vitest';
import type { Request } from 'express';
import {
  verifyApiKey,
  describeApiKeyConfigError,
  warnIfBothCredentialPathsConfigured,
} from '../verifyApiKey';
import { sha256Hasher } from '../hashers';
import type { ApiKeyRecord } from '../types';
import type { ApiKeyAuthConfigCore as ApiKeyAuthConfig } from '../types';

const PREFIX = 'cairn_';
const RAW = 'cairn_rawsecretvalue';
const HASH = sha256Hasher()(RAW);

function record(over: Partial<ApiKeyRecord> = {}): ApiKeyRecord {
  return { id: 'key-1', hash: HASH, ...over };
}

function baseConfig(over: Partial<ApiKeyAuthConfig> = {}): ApiKeyAuthConfig {
  return {
    prefix: PREFIX,
    lookup: async (h) => (h === HASH ? record() : null),
    ...over,
  };
}

function makeReq(partial: Partial<Request> = {}): Request {
  return { headers: {}, ip: '10.0.0.1', ...partial } as Request;
}

function bearer(key: string): Partial<Request> {
  return { headers: { authorization: `Bearer ${key}` } };
}

describe('verifyApiKey — presence flag', () => {
  it('absent credential → ok:false, present:false, reason:missing, 401', async () => {
    const out = await verifyApiKey(baseConfig(), makeReq());
    expect(out).toEqual({ ok: false, present: false, reason: 'missing', status: 401 });
  });

  it('malformed credential → ok:false, present:true, reason:malformed, 401', async () => {
    const out = await verifyApiKey(baseConfig(), makeReq({ headers: { authorization: 'Bearer' } }));
    expect(out).toEqual({ ok: false, present: true, reason: 'malformed', status: 401 });
  });
});

describe('verifyApiKey — success', () => {
  it('delegates indexed public-id credential verification to a raw authenticator without hashing the full credential', async () => {
    const rawAuthenticator = vi.fn(async (raw: string) => raw === 'cairn_key-1.secret-value-which-is-long-enough'
      ? { ok: true as const, record: { id: 'key-1', scopes: ['read'] } }
      : { ok: false as const, reason: 'not_found' as const });
    const hasher = vi.fn(() => { throw new Error('legacy hasher must not run'); });
    // No `lookup` here: PKG-149 Finding 2 made `rawAuthenticator` + `lookup`
    // mutually exclusive (config error), so the canonical path no longer
    // needs a dead `lookup` to satisfy the type — this IS that regression test.
    const out = await verifyApiKey(
      { prefix: 'cairn_', rawAuthenticator, hasher },
      makeReq(bearer('cairn_key-1.secret-value-which-is-long-enough')),
    );
    expect(out).toMatchObject({ ok: true, context: { principalId: 'key-1', scopes: ['read'] } });
    expect(rawAuthenticator).toHaveBeenCalledWith('cairn_key-1.secret-value-which-is-long-enough', expect.anything());
    expect(hasher).not.toHaveBeenCalled();
  });
  it('valid DB key → ok:true, context populated, record returned', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ scopes: ['read'] }) }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context).toMatchObject({ principalType: 'apiKey', principalId: 'key-1', keyId: 'key-1', scopes: ['read'] });
    expect(out.record?.id).toBe('key-1');
  });

  it('static key → ok:true, record null, service principal', async () => {
    const out = await verifyApiKey(
      {
        prefix: 'smh_',
        lookup: async () => null,
        staticKeys: [{ name: 'bootstrap', value: 'smh_boot', principalId: 'svc:boot' }],
      },
      makeReq(bearer('smh_boot')),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.record).toBeNull();
    expect(out.context).toEqual({ principalType: 'service', principalId: 'svc:boot', keyId: 'bootstrap' });
  });

  it('runs onAuthenticated to build the context', async () => {
    const out = await verifyApiKey(
      baseConfig({
        onAuthenticated: async (_req, key) => ({ principalType: 'user', principalId: `bot:${key.id}`, keyId: key.id }),
      }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.principalId).toBe('bot:key-1');
  });
});

describe('verifyApiKey — failures with reasons', () => {
  it('bad prefix → present:true, reason:bad_prefix, 401', async () => {
    const out = await verifyApiKey(baseConfig(), makeReq(bearer('nope_key')));
    expect(out).toMatchObject({ ok: false, present: true, reason: 'bad_prefix', status: 401 });
  });

  it('not found → reason:not_found, 401', async () => {
    const out = await verifyApiKey(baseConfig({ lookup: async () => null }), makeReq(bearer(RAW)));
    expect(out).toMatchObject({ ok: false, present: true, reason: 'not_found', status: 401 });
  });

  it('hash mismatch → reason:hash_mismatch, 401', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ hash: 'different' }) }),
      makeReq(bearer(RAW)),
    );
    expect(out).toMatchObject({ ok: false, reason: 'hash_mismatch', status: 401 });
  });

  it('expired → reason:expired, 401', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ expiresAt: new Date(Date.now() - 1000) }) }),
      makeReq(bearer(RAW)),
    );
    expect(out).toMatchObject({ ok: false, reason: 'expired', status: 401 });
  });

  it('invalid-date expiry → reason:expired', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ expiresAt: new Date('nope') }) }),
      makeReq(bearer(RAW)),
    );
    expect(out).toMatchObject({ ok: false, reason: 'expired' });
  });

  it('ip denied → reason:ip_denied, status 403', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ allowedIps: ['1.2.3.4'] }) }),
      makeReq({ ...bearer(RAW), ip: '10.0.0.1' }),
    );
    expect(out).toMatchObject({ ok: false, present: true, reason: 'ip_denied', status: 403 });
  });

  it('ip wildcard "*" allows any ip', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ allowedIps: ['*'] }) }),
      makeReq({ ...bearer(RAW), ip: '9.9.9.9' }),
    );
    expect(out.ok).toBe(true);
  });
});

describe('verifyApiKey — fail closed, never throws', () => {
  it('throwing lookup → ok:false, reason:error, present:true, 503 by default (no throw)', async () => {
    let out!: Awaited<ReturnType<typeof verifyApiKey>>;
    await expect(
      (async () => {
        out = await verifyApiKey(
          baseConfig({ lookup: async () => { throw new Error('db down'); } }),
          makeReq(bearer(RAW)),
        );
      })(),
    ).resolves.toBeUndefined();
    expect(out).toEqual({ ok: false, reason: 'error', present: true, status: 503 });
  });

  it('throwing hasher → ok:false, reason:error, present:true, 503 by default (no throw)', async () => {
    let out!: Awaited<ReturnType<typeof verifyApiKey>>;
    await expect(
      (async () => {
        out = await verifyApiKey(
          baseConfig({
            hasher: () => { throw new Error('hasher boom'); },
          }),
          makeReq(bearer(RAW)),
        );
      })(),
    ).resolves.toBeUndefined();
    expect(out).toEqual({ ok: false, reason: 'error', present: true, status: 503 });
  });

  it('errorStatus config overrides the default 503 (e.g. cairn maps error to 500)', async () => {
    const out = await verifyApiKey(
      baseConfig({
        errorStatus: 500,
        lookup: async () => { throw new Error('db down'); },
      }),
      makeReq(bearer(RAW)),
    );
    expect(out).toEqual({ ok: false, reason: 'error', present: true, status: 500 });
  });

  it('a throwing lookup NEVER results in an allow', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => { throw new Error('db down'); } }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(false);
  });
});

describe('verifyApiKey — IP allowlist normalization (IPv4-mapped IPv6)', () => {
  it('an allowlisted 203.0.113.7 is ALLOWED when req.ip is ::ffff:203.0.113.7', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ allowedIps: ['203.0.113.7'] }) }),
      makeReq({ ...bearer(RAW), ip: '::ffff:203.0.113.7' }),
    );
    expect(out.ok).toBe(true);
  });

  it('the mapped-prefix match is case-insensitive (::FFFF:)', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ allowedIps: ['203.0.113.7'] }) }),
      makeReq({ ...bearer(RAW), ip: '::FFFF:203.0.113.7' }),
    );
    expect(out.ok).toBe(true);
  });

  it('an unrelated IP is still denied (403)', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ allowedIps: ['203.0.113.7'] }) }),
      makeReq({ ...bearer(RAW), ip: '::ffff:198.51.100.9' }),
    );
    expect(out).toMatchObject({ ok: false, reason: 'ip_denied', status: 403 });
  });

  it('a malformed/absent req.ip fails closed (403), never allowed', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ allowedIps: ['203.0.113.7'] }) }),
      makeReq({ ...bearer(RAW), ip: undefined }),
    );
    expect(out).toMatchObject({ ok: false, reason: 'ip_denied', status: 403 });
  });
});

describe('verifyApiKey — hmacSecret passthrough (default context)', () => {
  it('copies record.hmacSecret into context.hmacSecret when present', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ hmacSecret: 's3cr3t' }) }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.hmacSecret).toBe('s3cr3t');
  });

  it('a record without hmacSecret leaves context.hmacSecret undefined, never a literal null', async () => {
    const out = await verifyApiKey(baseConfig(), makeReq(bearer(RAW)));
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.hmacSecret).toBeUndefined();
    expect(out.context.hmacSecret).not.toBeNull();
  });

  it('a record with hmacSecret: null also resolves to undefined, not a literal null', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ hmacSecret: null }) }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.hmacSecret).toBeUndefined();
  });

  it('other default-context fields are unchanged alongside hmacSecret (no regression)', async () => {
    const out = await verifyApiKey(
      baseConfig({
        lookup: async () => record({
          scopes: ['read'],
          hmacSecret: 'sek',
          rateLimitOverride: { windowMs: 1000, max: 5 },
        }),
      }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.principalType).toBe('apiKey');
    expect(out.context.principalId).toBe('key-1');
    expect(out.context.keyId).toBe('key-1');
    expect(out.context.scopes).toEqual(['read']);
    expect(out.context.rateLimitOverride).toEqual({ windowMs: 1000, max: 5 });
    expect(out.context.hmacSecret).toBe('sek');
  });
});

describe('verifyApiKey — meta passthrough', () => {
  it('copies record.meta into context.meta', async () => {
    const out = await verifyApiKey(
      baseConfig({ lookup: async () => record({ meta: { orgId: 'x' } }) }),
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.context.meta).toEqual({ orgId: 'x' });
    expect(out.record?.meta).toEqual({ orgId: 'x' });
  });
});

describe('verifyApiKey — rawAuthenticator unavailable (infra unreachable, e.g. an unloaded pepper ring)', () => {
  const unavailableAuthenticator = async () => ({ ok: false as const, reason: 'unavailable' as const });

  it('→ ok:false, reason:unavailable, present:true, 503 by default', async () => {
    const out = await verifyApiKey(
      { prefix: PREFIX, rawAuthenticator: unavailableAuthenticator },
      makeReq(bearer(RAW)),
    );
    expect(out).toEqual({ ok: false, reason: 'unavailable', present: true, status: 503 });
  });

  it('honors config.errorStatus, exactly like the internal error path', async () => {
    const out = await verifyApiKey(
      { prefix: PREFIX, rawAuthenticator: unavailableAuthenticator, errorStatus: 500 },
      makeReq(bearer(RAW)),
    );
    expect(out).toEqual({ ok: false, reason: 'unavailable', present: true, status: 500 });
  });

  it('never authenticates — ok is always false regardless of any other config', async () => {
    const out = await verifyApiKey(
      {
        prefix: PREFIX,
        rawAuthenticator: unavailableAuthenticator,
        onAuthenticated: () => { throw new Error('onAuthenticated must not run when unavailable'); },
      },
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(false);
  });
});

describe('ApiKeyAuthConfigCore — canonical vs legacy config shape (PKG-149 Finding 2)', () => {
  it('a canonical config compiles and runs WITHOUT a `lookup` at all', async () => {
    // No `lookup` key on this object literal — Finding 2's core ask: the
    // canonical path must not need a dead callback just to satisfy the type.
    const config: ApiKeyAuthConfig = {
      prefix: PREFIX,
      rawAuthenticator: async () => ({ ok: true, record: record() }),
    };
    expect(describeApiKeyConfigError(config)).toBeNull();
    const out = await verifyApiKey(config, makeReq(bearer(RAW)));
    expect(out.ok).toBe(true);
  });

  it('a legacy config (lookup, no rawAuthenticator) is still valid', () => {
    expect(describeApiKeyConfigError(baseConfig())).toBeNull();
  });

  it('supplying BOTH lookup and rawAuthenticator does NOT throw/error — rawAuthenticator wins, lookup is ignored (reversed: lookup used to be REQUIRED, so every canonical consumer had to supply a dead one)', async () => {
    const lookup = vi.fn(async () => { throw new Error('legacy lookup must not run'); });
    const out = await verifyApiKey(
      {
        prefix: PREFIX,
        lookup,
        rawAuthenticator: async () => ({ ok: true, record: record({ id: 'raw-authenticator-record' }) }),
      },
      makeReq(bearer(RAW)),
    );
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(out.record?.id).toBe('raw-authenticator-record'); // rawAuthenticator's record, not lookup's
    expect(lookup).not.toHaveBeenCalled();
  });

  it('supplying BOTH logs a ONE-TIME deprecation warning naming the config, via config.logger', async () => {
    const warn = vi.fn();
    const config: ApiKeyAuthConfig = {
      prefix: PREFIX,
      lookup: async () => record(),
      rawAuthenticator: async () => ({ ok: true, record: record() }),
      logger: { warn },
    };
    await verifyApiKey(config, makeReq(bearer(RAW)));
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toMatch(/rawAuthenticator.*lookup.*deprecated/is);

    // A second call against the SAME config object does not warn again.
    await verifyApiKey(config, makeReq(bearer(RAW)));
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('warnIfBothCredentialPathsConfigured never throws even if the logger throws', () => {
    const config = {
      lookup: async () => null,
      rawAuthenticator: async () => ({ ok: false as const }),
      logger: { warn: () => { throw new Error('logger boom'); } },
    };
    expect(() => warnIfBothCredentialPathsConfigured(config)).not.toThrow();
  });

  it('a config shaped like real consumers\' forced workaround (a dead `lookup` beside `rawAuthenticator`, e.g. cairn/smarthome/sano-os today) authenticates successfully with only a warning', async () => {
    const material = { keyId: 'k1', secret: 'sekret' };
    const config: ApiKeyAuthConfig = {
      prefix: PREFIX,
      // The forced-dead workaround these services carry today:
      lookup: async () => null,
      rawAuthenticator: async (rawKey) =>
        rawKey === `${PREFIX}${material.keyId}.${material.secret}`
          ? { ok: true, record: record({ id: material.keyId }) }
          : { ok: false, reason: 'not_found' },
    };
    const out = await verifyApiKey(
      config,
      makeReq(bearer(`${PREFIX}${material.keyId}.${material.secret}`)),
    );
    expect(out.ok).toBe(true);
  });

  it('supplying NEITHER lookup nor rawAuthenticator fails closed with reason "error"', async () => {
    const out = await verifyApiKey(
      { prefix: PREFIX } as ApiKeyAuthConfig,
      makeReq(bearer(RAW)),
    );
    expect(out).toEqual({ ok: false, reason: 'error', present: true, status: 503 });
  });

  it('describeApiKeyConfigError only flags NEITHER supplied — BOTH is valid (deprecated, not rejected)', () => {
    expect(
      describeApiKeyConfigError({ lookup: async () => null, rawAuthenticator: async () => ({ ok: false }) }),
    ).toBeNull();
    expect(describeApiKeyConfigError({})).toMatch(/either/);
  });
});
