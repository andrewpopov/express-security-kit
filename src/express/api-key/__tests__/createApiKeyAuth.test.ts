import { describe, it, expect, vi } from 'vitest';
import type { Request } from 'express';
import { createApiKeyAuth } from '../createApiKeyAuth';
import type { ApiKeyAuthConfig } from '../createApiKeyAuth';
import { sha256Hasher } from '../../../core/api-key/hashers';
import type { ApiKeyRecord } from '../../../core/api-key/types';

interface Outcome {
  status?: number;
  body?: any;
  nextCalled: boolean;
  req: Request;
}

function makeReq(partial: Partial<Request> = {}): Request {
  return { headers: {}, ip: '10.0.0.1', ...partial } as Request;
}

async function invoke(
  mw: ReturnType<typeof createApiKeyAuth>,
  req: Request,
): Promise<Outcome> {
  const outcome: Outcome = { nextCalled: false, req };
  await new Promise<void>((resolve) => {
    const res: any = {
      status(code: number) {
        outcome.status = code;
        return res;
      },
      json(payload: unknown) {
        outcome.body = payload;
        resolve();
        return res;
      },
    };
    mw(req, res, () => {
      outcome.nextCalled = true;
      resolve();
    });
  });
  return outcome;
}

const PREFIX = 'cairn_';
const RAW = 'cairn_rawsecretvalue';
const HASH = sha256Hasher()(RAW);

function baseConfig(over: Partial<ApiKeyAuthConfig> = {}): ApiKeyAuthConfig {
  return {
    prefix: PREFIX,
    lookup: async (h) => (h === HASH ? record() : null),
    ...over,
  };
}

function record(over: Partial<ApiKeyRecord> = {}): ApiKeyRecord {
  return { id: 'key-1', hash: HASH, ...over };
}

function bearer(key: string): Partial<Request> {
  return { headers: { authorization: `Bearer ${key}` } };
}

describe('createApiKeyAuth — missing key', () => {
  it('non-optional missing key → 401 + onFailure(missing)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(createApiKeyAuth(baseConfig({ onFailure })), makeReq());
    expect(out.status).toBe(401);
    expect(out.nextCalled).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'missing');
  });

  it('optional + genuinely absent header → next() unauthenticated (no securityContext)', async () => {
    const out = await invoke(
      createApiKeyAuth(baseConfig({ optional: true })),
      makeReq(),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.req.securityContext).toBeUndefined();
  });

  it('optional + PRESENT-but-malformed Bearer → 401 (not pass-through)', async () => {
    const onFailure = vi.fn();
    for (const header of ['Bearer', 'Basic abc', 'Bearer   ']) {
      const out = await invoke(
        createApiKeyAuth(baseConfig({ optional: true, onFailure })),
        makeReq({ headers: { authorization: header } }),
      );
      expect(out.nextCalled, `header="${header}"`).toBe(false);
      expect(out.status).toBe(401);
    }
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'malformed');
  });

  it('optional + valid key → authenticated', async () => {
    const out = await invoke(
      createApiKeyAuth(baseConfig({ optional: true })),
      makeReq(bearer(RAW)),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.req.securityContext?.principalType).toBe('apiKey');
  });

  it('non-optional + malformed Bearer → 401 + onFailure(malformed)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(baseConfig({ onFailure })),
      makeReq({ headers: { authorization: 'Bearer' } }),
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'malformed');
  });
});

describe('createApiKeyAuth — prefix', () => {
  it('bad prefix → 401 + onFailure(bad_prefix)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(baseConfig({ onFailure })),
      makeReq(bearer('wrong_prefixkey')),
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'bad_prefix');
  });
});

describe('createApiKeyAuth — valid DB key', () => {
  it('populates a default apiKey securityContext and calls next', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          lookup: async () =>
            record({
              scopes: ['read'],
              rateLimitOverride: { windowMs: 1000, max: 50 },
            }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.req.securityContext).toEqual({
      principalType: 'apiKey',
      principalId: 'key-1',
      keyId: 'key-1',
      scopes: ['read'],
      rateLimitOverride: { windowMs: 1000, max: 50 },
    });
  });

  it('reads the raw value from a non-authorization header (x-api-key)', async () => {
    const out = await invoke(
      createApiKeyAuth(baseConfig({ headerName: 'x-api-key' })),
      makeReq({ headers: { 'x-api-key': RAW } }),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.req.securityContext?.principalType).toBe('apiKey');
  });
});

describe('createApiKeyAuth — failure cases', () => {
  it('lookup returns null → 401 + onFailure(not_found)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(baseConfig({ onFailure, lookup: async () => null })),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'not_found');
  });

  it('record hash differs from computed hash → 401 + onFailure(hash_mismatch)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          onFailure,
          lookup: async () => record({ hash: 'different-hash' }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'hash_mismatch');
  });

  it('expired key → 401 + onFailure(expired)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          onFailure,
          lookup: async () => record({ expiresAt: new Date(Date.now() - 1000) }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'expired');
  });

  it('an invalid Date expiresAt is treated as expired → 401', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          onFailure,
          lookup: async () => record({ expiresAt: new Date('not a date') }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(401);
    expect(out.nextCalled).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'expired');
  });

  it('non-expired future expiry passes', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          lookup: async () => record({ expiresAt: new Date(Date.now() + 60_000) }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.nextCalled).toBe(true);
  });
});

describe('createApiKeyAuth — IP allowlist', () => {
  it('allows a listed IP', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({ lookup: async () => record({ allowedIps: ['10.0.0.1'] }) }),
      ),
      makeReq({ ...bearer(RAW), ip: '10.0.0.1' }),
    );
    expect(out.nextCalled).toBe(true);
  });

  it('denies an unlisted IP with 403 + onFailure(ip_denied)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          onFailure,
          lookup: async () => record({ allowedIps: ['1.2.3.4'] }),
        }),
      ),
      makeReq({ ...bearer(RAW), ip: '10.0.0.1' }),
    );
    expect(out.status).toBe(403);
    expect(out.nextCalled).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'ip_denied');
  });

  it('wildcard "*" allows any IP', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({ lookup: async () => record({ allowedIps: ['*'] }) }),
      ),
      makeReq({ ...bearer(RAW), ip: '9.9.9.9' }),
    );
    expect(out.nextCalled).toBe(true);
  });
});

describe('createApiKeyAuth — static bootstrap keys', () => {
  it('authenticates a static key as a service principal (before DB lookup)', async () => {
    const lookup = vi.fn(async () => null);
    const out = await invoke(
      createApiKeyAuth({
        prefix: 'smh_',
        lookup,
        staticKeys: [{ name: 'bootstrap', value: 'smh_bootstrapsecret', principalId: 'svc:bootstrap' }],
      }),
      makeReq(bearer('smh_bootstrapsecret')),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.req.securityContext).toEqual({
      principalType: 'service',
      principalId: 'svc:bootstrap',
      keyId: 'bootstrap',
    });
    expect(lookup).not.toHaveBeenCalled(); // short-circuits DB lookup
  });

  it('defaults principalId to the static key name', async () => {
    const out = await invoke(
      createApiKeyAuth({
        prefix: 'smh_',
        lookup: async () => null,
        staticKeys: [{ name: 'ci', value: 'smh_cisecret' }],
      }),
      makeReq(bearer('smh_cisecret')),
    );
    expect(out.req.securityContext?.principalId).toBe('ci');
  });
});

describe('createApiKeyAuth — onAuthenticated custom mapping', () => {
  it('supports minting a bot-user context (cairn)', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          onAuthenticated: async (_req, key) => ({
            principalType: 'user',
            principalId: `bot:${key.id}`,
            keyId: key.id,
            scopes: { org: 'acme', role: 'bot' },
          }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.req.securityContext).toMatchObject({
      principalType: 'user',
      principalId: 'bot:key-1',
      scopes: { org: 'acme', role: 'bot' },
    });
  });
});

describe('createApiKeyAuth — generic responses & fail-closed', () => {
  it('never leaks the failure reason in the response body', async () => {
    const cases: Array<[Request, Partial<ApiKeyAuthConfig>]> = [
      [makeReq(), {}], // missing
      [makeReq(bearer('nope_key')), {}], // bad prefix
      [makeReq(bearer(RAW)), { lookup: async () => null }], // not found
    ];
    for (const [req, over] of cases) {
      const out = await invoke(createApiKeyAuth(baseConfig(over)), req);
      expect(out.status).toBe(401);
      expect(out.body).toEqual({
        error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
      });
    }
  });

  it('fails CLOSED (503 by default, not 401) when lookup throws, calling onFailure(error)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          onFailure,
          lookup: async () => {
            throw new Error('db down');
          },
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(503);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service Unavailable' },
    });
    expect(out.nextCalled).toBe(false); // NOT allowed through
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'error');
  });

  it('fails CLOSED (503 by default, not 401) when hasher throws', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          hasher: () => {
            throw new Error('hasher boom');
          },
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(503);
    expect(out.nextCalled).toBe(false); // NOT allowed through
  });

  it('errorStatus config customizes the infrastructure-failure status (e.g. cairn -> 500)', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          errorStatus: 500,
          lookup: async () => {
            throw new Error('db down');
          },
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(500);
    expect(out.body).toEqual({
      error: { code: 'INTERNAL_ERROR', message: 'Internal Server Error' },
    });
  });

  it('onError customizes both status and body, and a throwing onError falls back to errorStatus', async () => {
    const warn = vi.fn();
    const outCustom = await invoke(
      createApiKeyAuth(
        baseConfig({
          onError: async () => ({ status: 502, body: { custom: true } }),
          lookup: async () => {
            throw new Error('db down');
          },
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(outCustom.status).toBe(502);
    expect(outCustom.body).toEqual({ custom: true });

    const outThrowing = await invoke(
      createApiKeyAuth(
        baseConfig({
          logger: { warn },
          onError: () => {
            throw new Error('onError boom');
          },
          lookup: async () => {
            throw new Error('db down');
          },
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(outThrowing.status).toBe(503); // falls back to the default, never an allow
    expect(outThrowing.nextCalled).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it('a throwing onFailure hook does not break the response', async () => {
    const warn = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          logger: { warn },
          onFailure: () => {
            throw new Error('audit boom');
          },
          lookup: async () => null,
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(401);
    expect(warn).toHaveBeenCalled();
  });

  it('an async onFailure rejection does not break the response', async () => {
    const warn = vi.fn();
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          logger: { warn },
          onFailure: () => Promise.reject(new Error('async audit boom')),
          lookup: async () => null,
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(401);
    await Promise.resolve();
    expect(warn).toHaveBeenCalled();
  });
});

describe('createApiKeyAuth — rawAuthenticator unavailable (infra unreachable, e.g. an unloaded pepper ring)', () => {
  const unavailableAuthenticator = async () => ({ ok: false as const, reason: 'unavailable' as const });

  it('fails CLOSED (503 by default, not 401), calling onFailure(unavailable)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createApiKeyAuth(baseConfig({ onFailure, rawAuthenticator: unavailableAuthenticator })),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(503);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service Unavailable' },
    });
    expect(out.nextCalled).toBe(false); // NOT allowed through
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'unavailable');
  });

  it('honors errorStatus, exactly like the internal error path', async () => {
    const out = await invoke(
      createApiKeyAuth(baseConfig({ errorStatus: 500, rawAuthenticator: unavailableAuthenticator })),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(500);
    expect(out.body).toEqual({
      error: { code: 'INTERNAL_ERROR', message: 'Internal Server Error' },
    });
  });

  it('honors onError override, exactly like the internal error path', async () => {
    const out = await invoke(
      createApiKeyAuth(
        baseConfig({
          rawAuthenticator: unavailableAuthenticator,
          onError: async () => ({ status: 502, body: { custom: true } }),
        }),
      ),
      makeReq(bearer(RAW)),
    );
    expect(out.status).toBe(502);
    expect(out.body).toEqual({ custom: true });
  });

  it('never authenticates, even in optional mode', async () => {
    const out = await invoke(
      createApiKeyAuth(baseConfig({ optional: true, rawAuthenticator: unavailableAuthenticator })),
      makeReq(bearer(RAW)),
    );
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(503);
  });
});
