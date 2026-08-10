import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Request } from 'express';
import { createRequestSigningVerifier } from '../createRequestSigningVerifier';
import { signRequest } from '../../../core/signing/signRequest';
import { MemoryNonceStore, NonceStore } from '../../../core/signing/nonceStore';

/**
 * PKG-151 follow-up (Codex review, findings 1 & 2). The core-level ordering
 * tests in `src/core/signing/__tests__/verifyRequestSignature.test.ts` prove
 * `verify()` defers `secret`/`body`/`nonceScope`/`hasRawBody` correctly GIVEN
 * already-lazy accessors. They can't catch a regression in the ADAPTER
 * itself — e.g. building the `RequestSignatureVerifyInput` object literal by
 * calling `bodySource(req)` / `nonceScope(req, ctx)` up front again, which is
 * exactly the bug this file guards against. These tests drive the real
 * `createRequestSigningVerifier` end to end with spies on the HOST-supplied
 * callbacks and a real `NonceStore`, so a reintroduced eager-evaluation bug
 * in the adapter's wiring fails here even if the core stays correct.
 *
 * A NEW file, not an edit to the existing (protected)
 * `createRequestSigningVerifier.test.ts` — that file's 23 tests are the
 * behaviour-preservation evidence for the PKG-151 carve and must stay
 * unmodified.
 */

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
  headers?: Record<string, string>;
}): Request {
  const method = over.method ?? 'POST';
  const url = over.url ?? '/api/lists/abc123/items?sort=name';
  const timestampMs = over.timestampMs ?? NOW;
  const nonce = over.nonce ?? 'nonce-abcdef12345678';
  const body = over.body ?? JSON.stringify({ name: 'Milk', qty: 2 });
  const secret = over.secret ?? SECRET;

  const { headers } = signRequest({ secret, method, url, timestampMs, nonce, body });

  return {
    method,
    originalUrl: url,
    rawBody: method === 'GET' || method === 'HEAD' ? undefined : body,
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

describe('createRequestSigningVerifier — lazy evaluation (adapter wiring)', () => {
  it('unresolved secret: the host bodySource and nonceScope callbacks are never invoked', async () => {
    const bodySource = vi.fn(() => JSON.stringify({ name: 'Milk', qty: 2 }));
    const nonceScope = vi.fn(() => 'global');
    const store = makeStore({ now: () => NOW });
    const consumeSpy = vi.spyOn(store, 'consume');
    const onFailure = vi.fn();
    const out = await invoke(
      createRequestSigningVerifier(
        baseConfig({ secret: () => undefined, bodySource, nonceScope, nonceStore: store, onFailure }),
      ),
      makeReq({}),
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'no_secret');
    expect(bodySource).not.toHaveBeenCalled();
    expect(nonceScope).not.toHaveBeenCalled();
    expect(consumeSpy).not.toHaveBeenCalled();
  });

  it('bad timestamp: the host bodySource callback is never invoked', async () => {
    const bodySource = vi.fn(() => JSON.stringify({ name: 'Milk', qty: 2 }));
    const req = makeReq({});
    (req.headers as any)['x-timestamp'] = 'not-a-number';
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ bodySource })),
      req,
    );
    expect(out.status).toBe(401);
    expect(bodySource).not.toHaveBeenCalled();
  });

  it('signature mismatch: the host nonceScope callback and the nonce store are never touched', async () => {
    const nonceScope = vi.fn(() => 'global');
    const store = makeStore({ now: () => NOW });
    const consumeSpy = vi.spyOn(store, 'consume');
    const req = makeReq({});
    (req.headers as any)['x-signature'] = 'f'.repeat(64); // valid shape, wrong value
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ nonceScope, nonceStore: store })),
      req,
    );
    expect(out.status).toBe(401);
    expect(nonceScope).not.toHaveBeenCalled();
    expect(consumeSpy).not.toHaveBeenCalled();
  });

  it('a throwing nonceScope on a malformed-nonce request still yields reason "nonce", not "error"', async () => {
    const nonceScope = vi.fn(() => {
      throw new Error('nonceScope must not run for a malformed request');
    });
    const onFailure = vi.fn();
    const req = makeReq({ nonce: 'short' });
    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ nonceScope, onFailure })),
      req,
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'nonce');
    expect(nonceScope).not.toHaveBeenCalled();
  });

  it('requireRawBody + a circular req.body: fails closed as "no_raw_body", never reaching the default bodySource that would throw on JSON.stringify', async () => {
    // Regression fixture for the exact scenario in the Codex review: with
    // requireRawBody + no req.rawBody + a circular parsed body, the PRE-carve
    // middleware (and this fix) returns 'no_raw_body' because hasRawBody() is
    // checked BEFORE bodySource() ever runs. The broken intermediate version
    // built the whole input object (calling the default bodySource, which
    // hits JSON.stringify(circular) and throws) before the requireRawBody
    // check ever ran, turning this into 'error' instead.
    const circular: Record<string, unknown> = { name: 'Milk' };
    circular.self = circular;
    const onFailure = vi.fn();

    const req = {
      method: 'POST',
      originalUrl: '/api/lists/abc123/items',
      rawBody: undefined,
      body: circular,
      headers: {
        'x-timestamp': String(NOW),
        'x-nonce': 'nonce-abcdef12345678',
        // Shape-only signature: requireRawBody fails BEFORE the HMAC
        // comparison is ever reached, so this value is never checked.
        'x-signature': 'a'.repeat(64),
      },
    } as unknown as Request;

    const out = await invoke(
      createRequestSigningVerifier(baseConfig({ requireRawBody: true, onFailure })),
      req,
    );
    expect(out.status).toBe(401);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'no_raw_body');
  });
});

describe('createRequestSigningVerifier — nonceStore late binding (finding 2)', () => {
  it('replacing config.nonceStore after construction takes effect on the next request', async () => {
    const storeA = makeStore({ now: () => NOW });
    const storeB = makeStore({ now: () => NOW });
    const config = baseConfig({ nonceStore: storeA });
    const mw = createRequestSigningVerifier(config);

    // First request: consumed against storeA.
    const first = await invoke(mw, makeReq({}));
    expect(first.nextCalled).toBe(true);
    expect(storeA.size).toBe(1);
    expect(storeB.size).toBe(0);

    // Host rotates the store on the SAME config object the middleware
    // holds a reference to — mimics a host recovering/rotating its store
    // after `createRequestSigningVerifier` has already been called.
    (config as { nonceStore: NonceStore }).nonceStore = storeB;

    // The exact same signed request again (same nonce/scope/timestamp). If
    // the middleware had captured storeA at construction time, this would be
    // rejected as a replay. Reading config.nonceStore fresh means it lands
    // in storeB, which has never seen this nonce, so it succeeds.
    const second = await invoke(mw, makeReq({}));
    expect(second.nextCalled).toBe(true);
    expect(storeB.size).toBe(1);
    expect(storeA.size).toBe(1); // storeA untouched by the second request
  });
});
