import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  createRequestSignatureVerifierCore,
  RequestSignatureVerifierConfigCore,
  RequestSignatureVerifyInput,
} from '../verifyRequestSignature';
import { signRequest } from '../signRequest';
import { MemoryNonceStore, NonceStore } from '../nonceStore';

const SECRET = 'test-signing-secret';
const NOW = 1700000000000;

const stores: MemoryNonceStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryNonceStore>) {
  const s = new MemoryNonceStore(...args);
  stores.push(s);
  return s;
}
afterEach(() => {
  while (stores.length) stores.pop()!.stop();
});

function baseConfig(
  over: Partial<RequestSignatureVerifierConfigCore> = {},
): RequestSignatureVerifierConfigCore {
  return {
    nonceStore: makeStore({ now: () => NOW }),
    now: () => NOW,
    ...over,
  };
}

// Proof the core is framework-free: every fixture here is a plain object
// shaped like RequestSignatureVerifyInput, never an Express (or Fastify)
// request. `signRequest` (the client-side helper) supplies correctly signed
// header values; individual tests then tamper with a single field.
function makeInput(
  over: {
    method?: string;
    url?: string;
    timestampMs?: number;
    nonce?: string;
    body?: string;
    secret?: string;
    nonceScope?: string;
    hasRawBody?: boolean;
    tamperSignature?: string;
  } = {},
): RequestSignatureVerifyInput {
  const method = over.method ?? 'POST';
  const url = over.url ?? '/api/lists/abc123/items?sort=name';
  const timestampMs = over.timestampMs ?? NOW;
  const nonce = over.nonce ?? 'nonce-abcdef12345678';
  const body = over.body ?? JSON.stringify({ name: 'Milk', qty: 2 });
  const secret = over.secret ?? SECRET;

  const { headers } = signRequest({ secret, method, url, timestampMs, nonce, body });

  return {
    method,
    url,
    timestampHeader: headers['X-Timestamp'],
    nonceHeader: headers['X-Nonce'],
    signatureHeader: over.tamperSignature ?? headers['X-Signature'],
    body: () => body,
    secret: () => secret,
    nonceScope: () => over.nonceScope ?? 'global',
    hasRawBody: () => over.hasRawBody ?? true,
  };
}

describe('createRequestSignatureVerifierCore — happy path', () => {
  it('accepts a valid signed POST → ok', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    expect(await core.verify(makeInput())).toEqual({ type: 'ok' });
  });

  it('accepts a valid signed GET (empty body) → ok', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const outcome = await core.verify(
      makeInput({
        method: 'GET',
        url: '/api/lists/abc123',
        nonce: 'nonce-getreq000001',
        body: '',
      }),
    );
    expect(outcome).toEqual({ type: 'ok' });
  });
});

describe('createRequestSignatureVerifierCore — failure reasons', () => {
  it('no_secret: an unresolved (undefined) secret fails closed', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput();
    input.secret = () => undefined;
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'no_secret' });
  });

  it('timestamp: missing header', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput();
    input.timestampHeader = undefined;
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'timestamp' });
  });

  it('timestamp: non-finite value', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput();
    input.timestampHeader = 'not-a-number';
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'timestamp' });
  });

  it('timestamp: non-positive value', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput();
    input.timestampHeader = '-5';
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'timestamp' });
  });

  it('skew: timestamp beyond maxSkewSeconds (default 300s)', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput({ timestampMs: NOW - 600_000 });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'skew' });
  });

  it('nonce: missing header', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput();
    input.nonceHeader = undefined;
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'nonce' });
  });

  it('nonce: malformed (too short for the default format)', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput({ nonce: 'short' });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'nonce' });
  });

  it('signature: missing header', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput();
    input.signatureHeader = undefined;
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'signature' });
  });

  it('signature: malformed (not 64-hex)', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput({ tamperSignature: 'xyz' });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'signature' });
  });

  it('signature: valid shape but wrong value', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput({ tamperSignature: 'f'.repeat(64) });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'signature' });
  });

  it('no_raw_body: requireRawBody true + hasRawBody false fails closed', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig({ requireRawBody: true }));
    const input = makeInput({ hasRawBody: false });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'no_raw_body' });
  });

  it('requireRawBody true + hasRawBody true proceeds (no no_raw_body failure)', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig({ requireRawBody: true }));
    const input = makeInput({ hasRawBody: true });
    expect(await core.verify(input)).toEqual({ type: 'ok' });
  });

  it('requireRawBody false (default): hasRawBody false does NOT fail closed with no_raw_body', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const input = makeInput({ hasRawBody: false });
    expect(await core.verify(input)).toEqual({ type: 'ok' });
  });
});

describe('createRequestSignatureVerifierCore — replay protection', () => {
  it('rejects a replayed nonce on second use (same scope)', async () => {
    const store = makeStore({ now: () => NOW });
    const core = createRequestSignatureVerifierCore(baseConfig({ nonceStore: store }));
    const input = makeInput();
    expect(await core.verify(input)).toEqual({ type: 'ok' });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'replay' });
  });

  it('same nonce under a DIFFERENT scope is accepted', async () => {
    const store = makeStore({ now: () => NOW });
    const core = createRequestSignatureVerifierCore(baseConfig({ nonceStore: store }));
    const a = makeInput({ nonceScope: 'keyA' });
    const b = makeInput({ nonceScope: 'keyB' });
    expect(await core.verify(a)).toEqual({ type: 'ok' });
    expect(await core.verify(b)).toEqual({ type: 'ok' });
  });

  it('consumes the nonce only AFTER signature validity (bad sig does not burn it)', async () => {
    const store = makeStore({ now: () => NOW });
    const core = createRequestSignatureVerifierCore(baseConfig({ nonceStore: store }));
    // First: valid nonce/timestamp but a tampered signature → fail, nonce NOT consumed.
    const bad = makeInput({ tamperSignature: 'a'.repeat(64) });
    expect(await core.verify(bad)).toEqual({ type: 'fail', reason: 'signature' });
    // The same nonce with a correct signature should still succeed.
    const good = makeInput();
    expect(await core.verify(good)).toEqual({ type: 'ok' });
  });
});

describe('createRequestSignatureVerifierCore — fail-closed on store error', () => {
  it('a throwing nonce store yields store_error, logs a warning', async () => {
    const throwingStore: NonceStore = {
      consume: () => Promise.reject(new Error('store down')),
    };
    const warn = vi.fn();
    const core = createRequestSignatureVerifierCore(
      baseConfig({ nonceStore: throwingStore, logger: { warn } }),
    );
    expect(await core.verify(makeInput())).toEqual({ type: 'fail', reason: 'store_error' });
    expect(warn).toHaveBeenCalled();
  });
});

describe('createRequestSignatureVerifierCore — non-ok store result fails closed', () => {
  it('consume resolving undefined (not "ok") → store_error', async () => {
    const badStore: NonceStore = {
      consume: () => Promise.resolve(undefined as unknown as 'ok'),
    };
    const warn = vi.fn();
    const core = createRequestSignatureVerifierCore(
      baseConfig({ nonceStore: badStore, logger: { warn } }),
    );
    expect(await core.verify(makeInput())).toEqual({ type: 'fail', reason: 'store_error' });
    expect(warn).toHaveBeenCalled();
  });

  it('consume resolving a garbage string → store_error', async () => {
    const badStore: NonceStore = {
      consume: () => Promise.resolve('weird' as unknown as 'ok'),
    };
    const core = createRequestSignatureVerifierCore(
      baseConfig({ nonceStore: badStore, logger: { warn: vi.fn() } }),
    );
    expect(await core.verify(makeInput())).toEqual({ type: 'fail', reason: 'store_error' });
  });
});

describe('createRequestSignatureVerifierCore — fail-closed on unexpected error', () => {
  it('a CR/LF-poisoned method reaching buildCanonicalString fails closed as error', async () => {
    const warn = vi.fn();
    const core = createRequestSignatureVerifierCore(baseConfig({ logger: { warn } }));
    const input = makeInput();
    // Passes every earlier check — secret/timestamp/nonce/signature-format
    // are all independent of `method` — but `buildCanonicalString` rejects a
    // raw CR/LF in `method`. Proves the core fails closed on ANY unexpected
    // throw, not just the documented failure reasons.
    input.method = 'POST\n';
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'error' });
    expect(warn).toHaveBeenCalled();
  });
});

// PKG-151 follow-up (Codex review): `secret`, `body`, `nonceScope`, and
// `hasRawBody` are zero-argument accessors precisely so `verify()` can defer
// calling them until the exact point the pre-carve middleware evaluated the
// equivalent code — never for a request that fails an earlier check. These
// tests pin that ordering with call-count/call-order assertions so a future
// change back to eager evaluation (e.g. destructuring all four up front)
// fails loudly instead of only showing up as a subtle behavior change.
describe('createRequestSignatureVerifierCore — lazy evaluation ordering', () => {
  function spiedInput(over: Parameters<typeof makeInput>[0] = {}) {
    const base = makeInput(over);
    const calls: string[] = [];
    const secretFn = vi.fn(() => {
      calls.push('secret');
      return base.secret();
    });
    const bodyFn = vi.fn(() => {
      calls.push('body');
      return base.body();
    });
    const nonceScopeFn = vi.fn(() => {
      calls.push('nonceScope');
      return base.nonceScope();
    });
    const hasRawBodyFn = vi.fn(() => {
      calls.push('hasRawBody');
      return base.hasRawBody();
    });
    const input: RequestSignatureVerifyInput = {
      ...base,
      secret: secretFn,
      body: bodyFn,
      nonceScope: nonceScopeFn,
      hasRawBody: hasRawBodyFn,
    };
    return { input, calls, secretFn, bodyFn, nonceScopeFn, hasRawBodyFn };
  }

  it('no_secret: body, nonceScope, hasRawBody, and the nonce store are never touched', async () => {
    const store = makeStore({ now: () => NOW });
    const consumeSpy = vi.spyOn(store, 'consume');
    const core = createRequestSignatureVerifierCore(baseConfig({ nonceStore: store }));
    const { input, secretFn, bodyFn, nonceScopeFn, hasRawBodyFn } = spiedInput();
    secretFn.mockImplementation(() => undefined);
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'no_secret' });
    expect(secretFn).toHaveBeenCalledTimes(1);
    expect(bodyFn).not.toHaveBeenCalled();
    expect(nonceScopeFn).not.toHaveBeenCalled();
    expect(hasRawBodyFn).not.toHaveBeenCalled();
    expect(consumeSpy).not.toHaveBeenCalled();
  });

  it('bad timestamp: body and nonceScope never invoked', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const { input, bodyFn, nonceScopeFn } = spiedInput();
    input.timestampHeader = undefined;
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'timestamp' });
    expect(bodyFn).not.toHaveBeenCalled();
    expect(nonceScopeFn).not.toHaveBeenCalled();
  });

  it('bad skew: body and nonceScope never invoked', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const { input, bodyFn, nonceScopeFn } = spiedInput({ timestampMs: NOW - 600_000 });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'skew' });
    expect(bodyFn).not.toHaveBeenCalled();
    expect(nonceScopeFn).not.toHaveBeenCalled();
  });

  it('malformed nonce: body and nonceScope never invoked', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const { input, bodyFn, nonceScopeFn } = spiedInput({ nonce: 'short' });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'nonce' });
    expect(bodyFn).not.toHaveBeenCalled();
    expect(nonceScopeFn).not.toHaveBeenCalled();
  });

  it('malformed signature (not 64-hex): body and nonceScope never invoked', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const { input, bodyFn, nonceScopeFn } = spiedInput({ tamperSignature: 'xyz' });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'signature' });
    expect(bodyFn).not.toHaveBeenCalled();
    expect(nonceScopeFn).not.toHaveBeenCalled();
  });

  it('requireRawBody failure: body never invoked', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig({ requireRawBody: true }));
    const { input, bodyFn, hasRawBodyFn, nonceScopeFn } = spiedInput({ hasRawBody: false });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'no_raw_body' });
    expect(hasRawBodyFn).toHaveBeenCalledTimes(1);
    expect(bodyFn).not.toHaveBeenCalled();
    expect(nonceScopeFn).not.toHaveBeenCalled();
  });

  it('signature mismatch: nonceScope never invoked and the store never consumes', async () => {
    const store = makeStore({ now: () => NOW });
    const consumeSpy = vi.spyOn(store, 'consume');
    const core = createRequestSignatureVerifierCore(baseConfig({ nonceStore: store }));
    const { input, bodyFn, nonceScopeFn } = spiedInput({ tamperSignature: 'f'.repeat(64) });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'signature' });
    // body() IS needed here — the canonical string (and thus the expected
    // HMAC) can't be computed without it — but nonceScope/consume must not
    // run for a request whose signature doesn't check out.
    expect(bodyFn).toHaveBeenCalledTimes(1);
    expect(nonceScopeFn).not.toHaveBeenCalled();
    expect(consumeSpy).not.toHaveBeenCalled();
  });

  it('success: secret, hasRawBody, body, nonceScope, and store.consume each invoked exactly once, in the documented order', async () => {
    const store = makeStore({ now: () => NOW });
    const { input, calls, secretFn, hasRawBodyFn, bodyFn, nonceScopeFn } = spiedInput({
      hasRawBody: true,
    });
    // Reuse the SAME `calls` array `spiedInput` already records
    // secret/hasRawBody/body/nonceScope into, so `consume`'s position lands
    // relative to them.
    const originalConsume = store.consume.bind(store);
    const consumeSpy = vi
      .spyOn(store, 'consume')
      .mockImplementation((...args: Parameters<NonceStore['consume']>) => {
        calls.push('consume');
        return originalConsume(...args);
      });
    const core = createRequestSignatureVerifierCore(
      baseConfig({ nonceStore: store, requireRawBody: true }),
    );

    expect(await core.verify(input)).toEqual({ type: 'ok' });
    expect(secretFn).toHaveBeenCalledTimes(1);
    expect(hasRawBodyFn).toHaveBeenCalledTimes(1);
    expect(bodyFn).toHaveBeenCalledTimes(1);
    expect(nonceScopeFn).toHaveBeenCalledTimes(1);
    expect(consumeSpy).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(['secret', 'hasRawBody', 'body', 'nonceScope', 'consume']);
  });

  it('a throwing nonceScope on an otherwise-malformed request still yields the malformed reason, not error', async () => {
    const core = createRequestSignatureVerifierCore(baseConfig());
    const { input, nonceScopeFn } = spiedInput({ nonce: 'short' });
    nonceScopeFn.mockImplementation(() => {
      throw new Error('nonceScope must not run for a malformed request');
    });
    expect(await core.verify(input)).toEqual({ type: 'fail', reason: 'nonce' });
    expect(nonceScopeFn).not.toHaveBeenCalled();
  });
});
