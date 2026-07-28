import { describe, it, expect, vi } from 'vitest';
import Fastify from 'fastify';
import { createApiKeyAuth } from '../createApiKeyAuth';
import type { FastifyApiKeyAuthConfig } from '../createApiKeyAuth';
import { sha256Hasher } from '../../../core/api-key/hashers';
import type { ApiKeyRecord } from '../../../core/api-key/types';

interface Outcome {
  status: number;
  body: any;
  handlerReached: boolean;
  securityContext: unknown;
}

/** Build a fresh Fastify app with `config`'s auth wired as a `preHandler`, inject one request, and close it. */
async function invoke(
  config: FastifyApiKeyAuthConfig,
  options: { headers?: Record<string, string>; remoteAddress?: string } = {},
): Promise<Outcome> {
  const app = Fastify();
  const state: { handlerReached: boolean; securityContext: unknown } = {
    handlerReached: false,
    securityContext: undefined,
  };
  app.route({
    method: 'GET',
    url: '/protected',
    preHandler: createApiKeyAuth(config),
    handler: async (request, reply) => {
      state.handlerReached = true;
      state.securityContext = request.securityContext;
      return reply.send({ ok: true });
    },
  });
  await app.ready();
  const res = await app.inject({
    method: 'GET',
    url: '/protected',
    headers: options.headers ?? {},
    remoteAddress: options.remoteAddress,
  });
  await app.close();
  return {
    status: res.statusCode,
    body: res.json(),
    handlerReached: state.handlerReached,
    securityContext: state.securityContext,
  };
}

const PREFIX = 'cairn_';
const RAW = 'cairn_rawsecretvalue';
const HASH = sha256Hasher()(RAW);

function baseConfig(over: Partial<FastifyApiKeyAuthConfig> = {}): FastifyApiKeyAuthConfig {
  return {
    prefix: PREFIX,
    lookup: async (h) => (h === HASH ? record() : null),
    ...over,
  };
}

function record(over: Partial<ApiKeyRecord> = {}): ApiKeyRecord {
  return { id: 'key-1', hash: HASH, ...over };
}

function bearer(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}` };
}

describe('fastify createApiKeyAuth — valid key', () => {
  it('valid key → handler runs, request.securityContext populated', async () => {
    const out = await invoke(baseConfig(), { headers: bearer(RAW) });
    expect(out.handlerReached).toBe(true);
    expect(out.securityContext).toEqual({
      principalType: 'apiKey',
      principalId: 'key-1',
      keyId: 'key-1',
      scopes: undefined,
      rateLimitOverride: undefined,
    });
  });
});

describe('fastify createApiKeyAuth — missing key', () => {
  it('missing key → 401 generic body, handler NOT reached', async () => {
    const onFailure = vi.fn();
    const out = await invoke(baseConfig({ onFailure }));
    expect(out.status).toBe(401);
    expect(out.body).toEqual({
      error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
    });
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'missing');
  });
});

describe('fastify createApiKeyAuth — invalid/expired/revoked', () => {
  it('unknown key (not_found) → 401, handler NOT reached, onFailure(not_found)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      baseConfig({ onFailure, lookup: async () => null }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(401);
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'not_found');
  });

  it('hash mismatch → 401, handler NOT reached, onFailure(hash_mismatch)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      baseConfig({ onFailure, lookup: async () => record({ hash: 'different-hash' }) }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(401);
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'hash_mismatch');
  });

  it('expired key → 401, handler NOT reached, onFailure(expired)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      baseConfig({
        onFailure,
        lookup: async () => record({ expiresAt: new Date(Date.now() - 1000) }),
      }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(401);
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'expired');
  });
});

describe('fastify createApiKeyAuth — IP allowlist (403)', () => {
  it('unlisted IP → 403, handler NOT reached, onFailure(ip_denied)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      baseConfig({ onFailure, lookup: async () => record({ allowedIps: ['1.2.3.4'] }) }),
      { headers: bearer(RAW), remoteAddress: '10.0.0.1' },
    );
    expect(out.status).toBe(403);
    expect(out.body).toEqual({
      error: { code: 'FORBIDDEN', message: 'Forbidden' },
    });
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'ip_denied');
  });

  it('listed IP → handler runs', async () => {
    const out = await invoke(
      baseConfig({ lookup: async () => record({ allowedIps: ['10.0.0.1'] }) }),
      { headers: bearer(RAW), remoteAddress: '10.0.0.1' },
    );
    expect(out.handlerReached).toBe(true);
  });
});

describe('fastify createApiKeyAuth — infrastructure failure (fail closed, 503 not 401)', () => {
  it('throwing lookup → 503, not 401', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      baseConfig({
        onFailure,
        lookup: async () => {
          throw new Error('db down');
        },
      }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(503);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service Unavailable' },
    });
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'error');
  });

  it('onError overrides both status and body', async () => {
    const out = await invoke(
      baseConfig({
        onError: async () => ({ status: 502, body: { custom: true } }),
        lookup: async () => {
          throw new Error('db down');
        },
      }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(502);
    expect(out.body).toEqual({ custom: true });
  });

  it('a throwing onError falls back to the default 503 body — response still sent', async () => {
    const warn = vi.fn();
    const out = await invoke(
      baseConfig({
        logger: { warn },
        onError: () => {
          throw new Error('onError boom');
        },
        lookup: async () => {
          throw new Error('db down');
        },
      }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(503);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service Unavailable' },
    });
    expect(out.handlerReached).toBe(false);
    expect(warn).toHaveBeenCalled();
  });
});

describe('fastify createApiKeyAuth — optional', () => {
  it('optional + genuinely absent credential → handler runs, no securityContext', async () => {
    const out = await invoke(baseConfig({ optional: true }));
    expect(out.handlerReached).toBe(true);
    expect(out.securityContext).toBeUndefined();
  });

  it('optional + present-but-invalid credential → still rejected (401)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      baseConfig({ optional: true, onFailure, lookup: async () => null }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(401);
    expect(out.handlerReached).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'not_found');
  });
});

describe('fastify createApiKeyAuth — audit hooks never affect the decision', () => {
  it('a throwing onFailure hook does not break the response', async () => {
    const warn = vi.fn();
    const out = await invoke(
      baseConfig({
        logger: { warn },
        onFailure: () => {
          throw new Error('audit boom');
        },
        lookup: async () => null,
      }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(401);
    expect(out.handlerReached).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it('an async onFailure rejection does not produce an unhandled rejection and does not break the response', async () => {
    const warn = vi.fn();
    const out = await invoke(
      baseConfig({
        logger: { warn },
        onFailure: () => Promise.reject(new Error('async audit boom')),
        lookup: async () => null,
      }),
      { headers: bearer(RAW) },
    );
    expect(out.status).toBe(401);
    await Promise.resolve();
    await Promise.resolve();
    expect(warn).toHaveBeenCalled();
  });
});
