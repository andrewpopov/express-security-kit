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
    body,
    secret,
    nonceScope: over.nonceScope ?? 'global',
    hasRawBody: over.hasRawBody ?? true,
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
    input.secret = undefined;
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
