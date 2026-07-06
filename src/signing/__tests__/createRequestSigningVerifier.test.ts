import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Request } from 'express';
import { createRequestSigningVerifier } from '../createRequestSigningVerifier';
import { signRequest } from '../signRequest';
import { MemoryNonceStore, NonceStore } from '../nonceStore';
import type { SecurityContext } from '../../types';

const stores: MemoryNonceStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryNonceStore>) {
  const s = new MemoryNonceStore(...args);
  stores.push(s);
  return s;
}
afterEach(() => {
  while (stores.length) stores.pop()!.stop();
});

const SECRET = 'test-signing-secret';
const NOW = 1700000000000;

interface Outcome {
  status?: number;
  body?: any;
  nextCalled: boolean;
  error?: unknown;
}

function makeReq(over: {
  method?: string;
  url?: string;
  timestampMs?: number;
  nonce?: string;
  body?: string;
  secret?: string;
  ctx?: SecurityContext;
  tamperBody?: string;
  headers?: Record<string, string>;
}): Request {
  const method = over.method ?? 'POST';
  const url = over.url ?? '/api/lists/abc123/items?sort=name';
  const timestampMs = over.timestampMs ?? NOW;
  const nonce = over.nonce ?? 'nonce-abcdef12345678';
  const body = over.body ?? JSON.stringify({ name: 'Milk', qty: 2 });
  const secret = over.secret ?? SECRET;

  const { headers } = signRequest({ secret, method, url, timestampMs, nonce, body });
  const rawBody = method === 'GET' || method === 'HEAD' ? undefined : over.tamperBody ?? body;

  return {
    method,
    originalUrl: url,
    rawBody,
    securityContext: over.ctx,
    headers: {
      'x-timestamp': headers['X-Timestamp'],
      'x-nonce': headers['X-Nonce'],
      'x-signature': headers['X-Signature'],
      ...over.headers,
    },
  } as unknown as Request;
}

async function invoke(
  mw: ReturnType<typeof createRequestSigningVerifier>,
  req: Request,
): Promise<Outcome> {
  const outcome: Outcome = { nextCalled: false };
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
    mw(req, res, (err?: unknown) => {
      outcome.nextCalled = true;
      outcome.error = err;
      resolve();
    });
  });
  return outcome;
}

function baseConfig(over: Record<string, unknown> = {}) {
  return {
    secret: SECRET,
    nonceStore: makeStore({ now: () => NOW }),
    now: () => NOW,
    ...over,
  } as Parameters<typeof createRequestSigningVerifier>[0];
}

describe('createRequestSigningVerifier — happy path', () => {
  it('accepts a valid signed POST → next with no error', async () => {
    const out = await invoke(
      createRequestSigningVerifier(baseConfig()),
      makeReq({}),
    );
    expect(out.nextCalled).toBe(true);
    expect(out.error).toBeUndefined();
    expect(out.status).toBeUndefined();
  });

  it('accepts a valid signed GET (empty body) → next', async () => {
    const out = await invoke(
      createRequestSigningVerifier(baseConfig()),
      makeReq({ method: 'GET', url: '/api/lists/abc123', nonce: 'nonce-getreq000001' }),
    );
    expect(out.nextCalled).toBe(true);
  });

  it('resolves a per-key secret from securityContext.hmacSecret', async () => {
    const perKeySecret = 'per-key-secret-xyz';
    const config = baseConfig({
      secret: (_req: Request, ctx: SecurityContext | undefined) => ctx?.hmacSecret ?? undefined,
    });
    const out = await invoke(
      createRequestSigningVerifier(config),
      makeReq({ secret: perKeySecret, ctx: { principalType: 'apiKey', keyId: 'k1', hmacSecret: perKeySecret } }),
    );
    expect(out.nextCalled).toBe(true);
  });
});

describe('createRequestSigningVerifier — rejections (generic 401)', () => {
  const expect401 = (out: Outcome) => {
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(401);
    expect(out.body).toEqual({ error: { code: 'UNAUTHORIZED', message: 'Unauthorized' } });
  };

  it('unresolved secret → 401 (no_secret)', async () => {
    const onFailure = vi.fn();
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ secret: () => undefined, onFailure })),
      makeReq({}),
    );
    expect401(out);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'no_secret');
  });

  it('bad signature → 401 (signature)', async () => {
    const onFailure = vi.fn();
    const req = makeReq({});
    (req.headers as any)['x-signature'] = 'f'.repeat(64); // valid shape, wrong value
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ onFailure })),
      req,
    );
    expect401(out);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'signature');
  });

  it('malformed signature (not 64-hex) → 401 (signature)', async () => {
    const req = makeReq({});
    (req.headers as any)['x-signature'] = 'xyz';
    const out = await invoke(createRequestSigningVerifier(baseConfig()), req);
    expect401(out);
  });

  it('skewed timestamp beyond maxSkew → 401 (skew)', async () => {
    const onFailure = vi.fn();
    // Sign with a timestamp 10 minutes before "now" (default skew 300s).
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ onFailure })),
      makeReq({ timestampMs: NOW - 600_000 }),
    );
    expect401(out);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'skew');
  });

  it('non-finite timestamp → 401 (timestamp)', async () => {
    const req = makeReq({});
    (req.headers as any)['x-timestamp'] = 'not-a-number';
    const onFailure = vi.fn();
    const out = await invoke(createRequestSigningVerifier(baseConfig({ onFailure })), req);
    expect401(out);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'timestamp');
  });

  it('missing nonce → 401 (nonce)', async () => {
    const req = makeReq({});
    delete (req.headers as any)['x-nonce'];
    const out = await invoke(createRequestSigningVerifier(baseConfig()), req);
    expect401(out);
  });

  it('malformed nonce (too short) → 401 (nonce)', async () => {
    // Sign with a bad nonce so the signature is valid but the format check fails.
    const onFailure = vi.fn();
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ onFailure })),
      makeReq({ nonce: 'short' }),
    );
    expect401(out);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'nonce');
  });

  it('tampered body (bodyHash mismatch) → 401 (signature)', async () => {
    // Sign over the real body but deliver a different rawBody.
    const out = await invoke(
      createRequestSigningVerifier(baseConfig()),
      makeReq({ tamperBody: JSON.stringify({ name: 'Milk', qty: 999 }) }),
    );
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(401);
  });
});

describe('createRequestSigningVerifier — replay protection', () => {
  it('rejects a replayed nonce on second use (same scope)', async () => {
    const store = makeStore({ now: () => NOW });
    const config = baseConfig({ nonceStore: store });
    const mw = createRequestSigningVerifier(config);
    const first = await invoke(mw, makeReq({}));
    expect(first.nextCalled).toBe(true);
    // Identical signed request again.
    const second = await invoke(mw, makeReq({}));
    expect(second.nextCalled).toBe(false);
    expect(second.status).toBe(401);
  });

  it('same nonce under a DIFFERENT scope is accepted', async () => {
    const store = makeStore({ now: () => NOW });
    const mw = createRequestSigningVerifier(
      baseConfig({
        nonceStore: store,
        nonceScope: (_req: Request, ctx: SecurityContext | undefined) => ctx?.keyId ?? 'global',
      }),
    );
    const a = await invoke(mw, makeReq({ ctx: { principalType: 'apiKey', keyId: 'keyA', hmacSecret: SECRET } }));
    const b = await invoke(mw, makeReq({ ctx: { principalType: 'apiKey', keyId: 'keyB', hmacSecret: SECRET } }));
    expect(a.nextCalled).toBe(true);
    expect(b.nextCalled).toBe(true);
  });

  it('consumes the nonce only AFTER signature validity (bad sig does not burn it)', async () => {
    const store = makeStore({ now: () => NOW });
    const mw = createRequestSigningVerifier(baseConfig({ nonceStore: store }));
    // First: valid request but tamper the signature → 401, nonce NOT consumed.
    const badReq = makeReq({});
    (badReq.headers as any)['x-signature'] = 'a'.repeat(64);
    const bad = await invoke(mw, badReq);
    expect(bad.status).toBe(401);
    // Now the same nonce with a correct signature should still succeed.
    const good = await invoke(mw, makeReq({}));
    expect(good.nextCalled).toBe(true);
  });
});

describe('createRequestSigningVerifier — fail-closed on store error', () => {
  it('rejects (401) when the nonce store throws, does not call next', async () => {
    const throwingStore: NonceStore = {
      consume: () => Promise.reject(new Error('store down')),
    };
    const onFailure = vi.fn();
    const warn = vi.fn();
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ nonceStore: throwingStore, onFailure, logger: { warn } })),
      makeReq({}),
    );
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'store_error');
    expect(warn).toHaveBeenCalled();
  });
});

describe('createRequestSigningVerifier — non-ok store result fails closed', () => {
  it('rejects (401) when consume resolves undefined (not "ok")', async () => {
    const badStore: NonceStore = {
      consume: () => Promise.resolve(undefined as unknown as 'ok'),
    };
    const onFailure = vi.fn();
    const warn = vi.fn();
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ nonceStore: badStore, onFailure, logger: { warn } })),
      makeReq({}),
    );
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'store_error');
    expect(warn).toHaveBeenCalled();
  });

  it('rejects (401) on a garbage string result', async () => {
    const badStore: NonceStore = {
      consume: () => Promise.resolve('weird' as unknown as 'ok'),
    };
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ nonceStore: badStore, logger: { warn: vi.fn() } })),
      makeReq({}),
    );
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(401);
  });
});

describe('createRequestSigningVerifier — static vs resolver secret', () => {
  it('static string secret works', async () => {
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ secret: SECRET })),
      makeReq({}),
    );
    expect(out.nextCalled).toBe(true);
  });

  it('async resolver secret works', async () => {
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ secret: async () => SECRET })),
      makeReq({}),
    );
    expect(out.nextCalled).toBe(true);
  });
});
