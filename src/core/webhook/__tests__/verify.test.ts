import { createHash, createHmac, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';

import { verifyWebhookSignature } from '../verify';
import type {
  Ed25519Config,
  HmacSha256Config,
  ReplayConfig,
  WebhookHeaders,
} from '../verify';
import { MemoryNonceStore } from '../../signing/nonceStore';
import type { NonceStore } from '../../signing/nonceStore';

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const SECRET = 'hmac-shared-secret';

function hmacSign(body: string | Buffer, secret = SECRET): string {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  return 'sha256=' + createHmac('sha256', secret).update(buf).digest('hex');
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** A NonceStore whose consume() is a vitest spy so call-count/order can be asserted. */
function spyStore(impl?: (scope: string, nonce: string, ttlMs: number) => Promise<'ok' | 'replay'>) {
  const consume = vi.fn(impl ?? (async () => 'ok' as const));
  const store: NonceStore = { consume };
  return { store, consume };
}

function throwingStore(): NonceStore {
  return {
    consume: vi.fn(async () => {
      throw new Error('ECONNRESET');
    }),
  };
}

const ed25519KeyPair = generateKeyPairSync('ed25519');
const ED25519_PUBLIC_KEY_HEX = ed25519KeyPair.publicKey
  .export({ type: 'spki', format: 'der' })
  .subarray(12)
  .toString('hex');

function ed25519Sign(timestamp: string, body: string | Buffer): string {
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  const message = Buffer.concat([Buffer.from(timestamp, 'utf8'), bodyBuf]);
  return cryptoSign(null, message, ed25519KeyPair.privateKey).toString('hex');
}

function hmacConfig(overrides: Partial<HmacSha256Config> = {}): HmacSha256Config {
  return { scheme: 'hmac-sha256', secret: SECRET, ...overrides };
}

function ed25519Config(overrides: Partial<Ed25519Config> = {}): Ed25519Config {
  return {
    scheme: 'ed25519',
    publicKey: ED25519_PUBLIC_KEY_HEX,
    timestamp: { header: 'x-signature-timestamp', maxSkewSeconds: 300, now: () => nowMs },
    ...overrides,
  };
}

let nowMs = 1_700_000_000_000; // fixed clock for ed25519 timestamp tests
const nowSeconds = () => Math.floor(nowMs / 1000);

// ===========================================================================
// HMAC-SHA256
// ===========================================================================

describe('verifyWebhookSignature — hmac-sha256', () => {
  it('happy path: valid signature over the raw body verifies', async () => {
    const body = '{"event":"push"}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: true });
  });

  it('accepts a Buffer rawBody', async () => {
    const body = Buffer.from('{"event":"push"}', 'utf8');
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: true });
  });

  it('rejects a bad (forged) signature', async () => {
    const body = '{"event":"push"}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign('different body') };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('rejects a signature of the wrong hex length (defense-in-depth length pre-check)', async () => {
    const body = '{"event":"push"}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': 'sha256=abcd1234' };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('rejects a non-hex signature value', async () => {
    const body = '{"event":"push"}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': 'sha256=' + 'zz'.repeat(32) };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('rejects the wrong digest prefix even with an otherwise-valid hex tail', async () => {
    const body = '{"event":"push"}';
    const validHex = hmacSign(body).slice('sha256='.length);
    const headers: WebhookHeaders = { 'x-hub-signature-256': 'sha1=' + validHex };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('missing signature header -> missing_signature', async () => {
    const outcome = await verifyWebhookSignature({
      rawBody: '{}',
      headers: {},
      config: hmacConfig(),
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_signature' });
  });

  it('signature header present as an array -> rejected as missing_signature, not guessed', async () => {
    const body = '{}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': [hmacSign(body), hmacSign(body)] };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: false, reason: 'missing_signature' });
  });

  it('signature header present as a comma-joined duplicate -> rejected as missing_signature', async () => {
    const body = '{}';
    const sig = hmacSign(body);
    const headers: WebhookHeaders = { 'x-hub-signature-256': `${sig}, ${sig}` };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: hmacConfig() });
    expect(outcome).toEqual({ ok: false, reason: 'missing_signature' });
  });

  it('undefined rawBody (no raw-body capture) -> missing_body, distinct from a legitimate empty body', async () => {
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign('') };
    const missing = await verifyWebhookSignature({
      rawBody: undefined,
      headers,
      config: hmacConfig(),
    });
    expect(missing).toEqual({ ok: false, reason: 'missing_body' });

    // The SAME signature, but over a genuinely empty body that IS captured,
    // verifies successfully.
    const empty = await verifyWebhookSignature({ rawBody: '', headers, config: hmacConfig() });
    expect(empty).toEqual({ ok: true });
  });

  it('missing secret (resolver returns undefined) -> missing_secret', async () => {
    const body = '{}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers,
      config: hmacConfig({ secret: () => undefined }),
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_secret' });
  });

  it('a throwing secret resolver also surfaces as missing_secret, never crashes', async () => {
    const body = '{}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers,
      config: hmacConfig({
        secret: () => {
          throw new Error('boom');
        },
      }),
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_secret' });
  });

  it('an async secret resolver is awaited', async () => {
    const body = '{}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers,
      config: hmacConfig({ secret: async () => SECRET }),
    });
    expect(outcome).toEqual({ ok: true });
  });

  it('supports a custom signature header and digest prefix', async () => {
    const body = '{}';
    const sig = createHmac('sha256', SECRET).update(body).digest('hex');
    const headers: WebhookHeaders = { 'x-custom-sig': `v1=${sig}` };
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers,
      config: hmacConfig({ signatureHeader: 'x-custom-sig', digestPrefix: 'v1=' }),
    });
    expect(outcome).toEqual({ ok: true });
  });
});

// ===========================================================================
// Ed25519
// ===========================================================================

describe('verifyWebhookSignature — ed25519', () => {
  function ed25519Headers(body: string, ts: string = String(nowSeconds())): WebhookHeaders {
    return {
      'x-signature-ed25519': ed25519Sign(ts, body),
      'x-signature-timestamp': ts,
    };
  }

  it('happy path: valid ed25519 signature over timestamp+body verifies', async () => {
    const body = '{"type":1}';
    const headers = ed25519Headers(body);
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: true });
  });

  it('rejects a bad (forged) signature', async () => {
    const body = '{"type":1}';
    const ts = String(nowSeconds());
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(ts, 'different body'),
      'x-signature-timestamp': ts,
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('malformed signature hex does not crash — surfaces as bad_signature', async () => {
    const body = '{"type":1}';
    const headers: WebhookHeaders = {
      'x-signature-ed25519': 'not-hex-at-all',
      'x-signature-timestamp': String(nowSeconds()),
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('malformed configured public key does not crash — surfaces as missing_public_key, not bad_signature', async () => {
    const body = '{"type":1}';
    const headers = ed25519Headers(body);
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers,
      config: ed25519Config({ publicKey: 'not-hex-at-all' }),
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_public_key' });
  });

  it('missing public key (resolver returns undefined) -> missing_public_key', async () => {
    const body = '{"type":1}';
    const headers = ed25519Headers(body);
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers,
      config: ed25519Config({ publicKey: () => undefined }),
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_public_key' });
  });

  it('missing timestamp header -> missing_timestamp', async () => {
    const body = '{"type":1}';
    const headers: WebhookHeaders = { 'x-signature-ed25519': 'a'.repeat(128) };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'missing_timestamp' });
  });

  it('malformed timestamp VALUE (authenticated but non-numeric) -> invalid_timestamp', async () => {
    const body = '{"type":1}';
    const ts = 'not-a-number';
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(ts, body),
      'x-signature-timestamp': ts,
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'invalid_timestamp' });
  });

  it('a fractional timestamp value is rejected as invalid_timestamp', async () => {
    const body = '{"type":1}';
    const ts = `${nowSeconds()}.5`;
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(ts, body),
      'x-signature-timestamp': ts,
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'invalid_timestamp' });
  });

  it('a signed timestamp value is rejected as invalid_timestamp', async () => {
    const body = '{"type":1}';
    const ts = `-${nowSeconds()}`;
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(ts, body),
      'x-signature-timestamp': ts,
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'invalid_timestamp' });
  });

  it('a stale (out-of-window) but well-formed and correctly-signed timestamp -> stale_timestamp', async () => {
    const body = '{"type":1}';
    const staleTs = String(nowSeconds() - 10_000); // 10,000s ago, way past the 300s window
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(staleTs, body),
      'x-signature-timestamp': staleTs,
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: false, reason: 'stale_timestamp' });
  });

  it('a future timestamp within the skew window is accepted', async () => {
    const body = '{"type":1}';
    const futureTs = String(nowSeconds() + 100);
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(futureTs, body),
      'x-signature-timestamp': futureTs,
    };
    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
    expect(outcome).toEqual({ ok: true });
  });

  describe('timestamp reparse-immunity — tampering is caught by SIGNATURE failure, not silently normalized', () => {
    it('a leading-zero variant of a validly-signed timestamp is rejected (bad_signature), not accepted as the same value', async () => {
      const body = '{"type":1}';
      const ts = String(nowSeconds());
      const tampered = '0' + ts; // same numeric value, different signed bytes
      const headers: WebhookHeaders = {
        'x-signature-ed25519': ed25519Sign(ts, body), // signed over the ORIGINAL bytes
        'x-signature-timestamp': tampered, // request carries the TAMPERED bytes
      };
      const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
      expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
    });

    it('a whitespace-padded variant of a validly-signed timestamp is rejected (bad_signature), not trimmed and accepted', async () => {
      const body = '{"type":1}';
      const ts = String(nowSeconds());
      const tampered = ` ${ts} `;
      const headers: WebhookHeaders = {
        'x-signature-ed25519': ed25519Sign(ts, body),
        'x-signature-timestamp': tampered,
      };
      const outcome = await verifyWebhookSignature({ rawBody: body, headers, config: ed25519Config() });
      expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
    });
  });

  it('undefined rawBody -> missing_body, distinct from a legitimate empty body', async () => {
    const ts = String(nowSeconds());
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(ts, ''),
      'x-signature-timestamp': ts,
    };
    const missing = await verifyWebhookSignature({
      rawBody: undefined,
      headers,
      config: ed25519Config(),
    });
    expect(missing).toEqual({ ok: false, reason: 'missing_body' });

    const empty = await verifyWebhookSignature({ rawBody: '', headers, config: ed25519Config() });
    expect(empty).toEqual({ ok: true });
  });
});

// ===========================================================================
// Replay protection
// ===========================================================================

describe('verifyWebhookSignature — replay protection (hmac-sha256)', () => {
  function withReplay(store: NonceStore, overrides: Partial<ReplayConfig> = {}): HmacSha256Config {
    return hmacConfig({ replay: { store, scope: 'gh-webhook', ttlMs: 60_000, ...overrides } });
  }

  it('first delivery ok, byte-identical resend -> replay', async () => {
    const store = new MemoryNonceStore();
    const body = '{"event":"push"}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const config = withReplay(store);

    const first = await verifyWebhookSignature({ rawBody: body, headers, config });
    const second = await verifyWebhookSignature({ rawBody: body, headers, config });
    expect(first).toEqual({ ok: true });
    expect(second).toEqual({ ok: false, reason: 'replay' });
    store.dispose();
  });

  it('store.consume() throwing -> store_unavailable, NEVER replay', async () => {
    const body = '{"event":"push"}';
    const headers: WebhookHeaders = { 'x-hub-signature-256': hmacSign(body) };
    const config = withReplay(throwingStore());

    const outcome = await verifyWebhookSignature({ rawBody: body, headers, config });
    expect(outcome).toEqual({ ok: false, reason: 'store_unavailable' });
  });

  it('the replay id is AUTHENTICATED: mutating an unauthenticated header does not change the outcome', async () => {
    const store = new MemoryNonceStore();
    const body = '{"event":"push"}';
    const config = withReplay(store);

    const headersA: WebhookHeaders = {
      'x-hub-signature-256': hmacSign(body),
      'x-github-delivery': 'delivery-id-AAAA',
    };
    const first = await verifyWebhookSignature({ rawBody: body, headers: headersA, config });
    expect(first).toEqual({ ok: true });

    // Same body/signature, but a DIFFERENT value for an unauthenticated
    // delivery-id header — if replay were (incorrectly) keyed off that
    // header, this would be treated as a fresh delivery. It must still be
    // caught as a replay.
    const headersB: WebhookHeaders = {
      'x-hub-signature-256': hmacSign(body),
      'x-github-delivery': 'delivery-id-BBBB',
    };
    const second = await verifyWebhookSignature({ rawBody: body, headers: headersB, config });
    expect(second).toEqual({ ok: false, reason: 'replay' });
    store.dispose();
  });

  it('with idFromVerifiedBody, distinct verified-body ids do not collide', async () => {
    const store = new MemoryNonceStore();
    const idFromVerifiedBody = (body: string | Buffer) =>
      (JSON.parse(body.toString()) as { id: string }).id;
    const config = withReplay(store, { idFromVerifiedBody });

    const bodyA = JSON.stringify({ id: 'evt-1' });
    const bodyB = JSON.stringify({ id: 'evt-2' });
    const outcomeA = await verifyWebhookSignature({
      rawBody: bodyA,
      headers: { 'x-hub-signature-256': hmacSign(bodyA) },
      config,
    });
    const outcomeB = await verifyWebhookSignature({
      rawBody: bodyB,
      headers: { 'x-hub-signature-256': hmacSign(bodyB) },
      config,
    });
    expect(outcomeA).toEqual({ ok: true });
    expect(outcomeB).toEqual({ ok: true });
    store.dispose();
  });

  it('idFromVerifiedBody returning undefined -> missing_replay_id', async () => {
    const store = new MemoryNonceStore();
    const config = withReplay(store, { idFromVerifiedBody: () => undefined });
    const body = '{}';
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers: { 'x-hub-signature-256': hmacSign(body) },
      config,
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_replay_id' });
    store.dispose();
  });

  it('default replay id is derivable as sha256hex(verified signature digest)', async () => {
    // Documents the default derivation so a consumer migrating off a
    // different store can compute compatible ids if ever needed.
    const store = new MemoryNonceStore();
    const body = '{"event":"push"}';
    const sig = hmacSign(body);
    const expectedId = sha256Hex(sig.slice('sha256='.length));
    const consumeSpy = vi.spyOn(store, 'consume');
    const config = withReplay(store);
    await verifyWebhookSignature({ rawBody: body, headers: { 'x-hub-signature-256': sig }, config });
    expect(consumeSpy).toHaveBeenCalledWith('gh-webhook', expectedId, 60_000);
    store.dispose();
  });

  it('supports an async scope resolver', async () => {
    const { store, consume } = spyStore();
    const body = '{}';
    const config = withReplay(store, { scope: async () => 'resolved-scope' });
    await verifyWebhookSignature({ rawBody: body, headers: { 'x-hub-signature-256': hmacSign(body) }, config });
    expect(consume).toHaveBeenCalledWith('resolved-scope', expect.any(String), 60_000);
  });
});

describe('verifyWebhookSignature — replay protection (ed25519)', () => {
  it('first delivery ok, byte-identical resend -> replay', async () => {
    const store = new MemoryNonceStore();
    const body = '{"type":1}';
    const ts = String(nowSeconds());
    const headers: WebhookHeaders = {
      'x-signature-ed25519': ed25519Sign(ts, body),
      'x-signature-timestamp': ts,
    };
    const config = ed25519Config({ replay: { store, scope: 'discord', ttlMs: 60_000 } });

    const first = await verifyWebhookSignature({ rawBody: body, headers, config });
    const second = await verifyWebhookSignature({ rawBody: body, headers, config });
    expect(first).toEqual({ ok: true });
    expect(second).toEqual({ ok: false, reason: 'replay' });
    store.dispose();
  });
});

// ===========================================================================
// Ordering (C4) — an unauthenticated request must NEVER reach the nonce store
// ===========================================================================

describe('verifyWebhookSignature — ordering', () => {
  it('a bad-signature hmac request never calls store.consume()', async () => {
    const { store, consume } = spyStore();
    const body = '{"event":"push"}';
    const config = hmacConfig({ replay: { store, scope: 's', ttlMs: 60_000 } });
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers: { 'x-hub-signature-256': hmacSign('forged body') },
      config,
    });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
    expect(consume).not.toHaveBeenCalled();
  });

  it('a bad-signature ed25519 request never calls store.consume()', async () => {
    const { store, consume } = spyStore();
    const body = '{"type":1}';
    const ts = String(nowSeconds());
    const config = ed25519Config({ replay: { store, scope: 's', ttlMs: 60_000 } });
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers: {
        'x-signature-ed25519': ed25519Sign(ts, 'forged body'),
        'x-signature-timestamp': ts,
      },
      config,
    });
    expect(outcome).toEqual({ ok: false, reason: 'bad_signature' });
    expect(consume).not.toHaveBeenCalled();
  });

  it('a missing-secret request never calls store.consume()', async () => {
    const { store, consume } = spyStore();
    const body = '{}';
    const config = hmacConfig({
      secret: () => undefined,
      replay: { store, scope: 's', ttlMs: 60_000 },
    });
    const outcome = await verifyWebhookSignature({
      rawBody: body,
      headers: { 'x-hub-signature-256': hmacSign(body) },
      config,
    });
    expect(outcome).toEqual({ ok: false, reason: 'missing_secret' });
    expect(consume).not.toHaveBeenCalled();
  });
});
