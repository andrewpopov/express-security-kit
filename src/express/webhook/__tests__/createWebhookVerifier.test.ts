import { createHmac, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';
import type { Request } from 'express';
import { createWebhookVerifier } from '../createWebhookVerifier';
import type { WebhookVerifierConfig } from '../createWebhookVerifier';
import type { NonceStore } from '../../../core/signing/nonceStore';

interface Outcome {
  status?: number;
  body?: unknown;
  nextCalled: boolean;
  req: Request;
}

function makeReq(partial: Partial<Request> = {}): Request {
  return { headers: {}, ...partial } as Request;
}

async function invoke(
  mw: ReturnType<typeof createWebhookVerifier>,
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

const SECRET = 'hmac-shared-secret';

function hmacSign(body: string | Buffer, secret = SECRET): string {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  return 'sha256=' + createHmac('sha256', secret).update(buf).digest('hex');
}

function baseConfig(over: Partial<WebhookVerifierConfig> = {}): WebhookVerifierConfig {
  return {
    scheme: 'hmac-sha256',
    secret: SECRET,
    ...over,
  } as WebhookVerifierConfig;
}

function throwingStore(): NonceStore {
  return {
    consume: vi.fn(async () => {
      throw new Error('ECONNRESET');
    }),
  };
}

describe('createWebhookVerifier — happy path', () => {
  it('valid signature → next() called, no response sent', async () => {
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign(body) },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(createWebhookVerifier(baseConfig()), req);
    expect(out.nextCalled).toBe(true);
    expect(out.status).toBeUndefined();
    expect(out.body).toBeUndefined();
  });

  it('reads the raw body from req.rawBody by default', async () => {
    const body = Buffer.from('{"event":"push"}', 'utf8');
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign(body) },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(createWebhookVerifier(baseConfig()), req);
    expect(out.nextCalled).toBe(true);
  });

  it('a custom rawBody extractor overrides the req.rawBody default', async () => {
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign(body) },
      // req.rawBody deliberately wrong/absent — the extractor supplies it.
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier(baseConfig({ rawBody: () => body })),
      req,
    );
    expect(out.nextCalled).toBe(true);
  });
});

describe('createWebhookVerifier — 401 (per-request verification failures)', () => {
  it('bad_signature → 401 generic body, next NOT called', async () => {
    const onFailure = vi.fn();
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign('different body') },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(createWebhookVerifier(baseConfig({ onFailure })), req);
    expect(out.status).toBe(401);
    expect(out.nextCalled).toBe(false);
    expect(out.body).toEqual({ error: { code: 'UNAUTHORIZED', message: 'Unauthorized' } });
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'bad_signature');
  });

  it('missing_body (no raw-body capture) → 401', async () => {
    const onFailure = vi.fn();
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign('irrelevant') },
      // no rawBody set at all
    } as Partial<Request>);
    const out = await invoke(createWebhookVerifier(baseConfig({ onFailure })), req);
    expect(out.status).toBe(401);
    expect(out.nextCalled).toBe(false);
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'missing_body');
  });
});

describe('createWebhookVerifier — 503 (unavailable, not a forgery signal)', () => {
  it('missing_secret → 503', async () => {
    const onFailure = vi.fn();
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign(body) },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier(baseConfig({ secret: () => undefined, onFailure })),
      req,
    );
    expect(out.status).toBe(503);
    expect(out.nextCalled).toBe(false);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service unavailable' },
    });
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'missing_secret');
  });

  it('store_unavailable (nonce store throws) → 503', async () => {
    const onFailure = vi.fn();
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign(body) },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier(
        baseConfig({
          onFailure,
          replay: { store: throwingStore(), scope: 'gh', ttlMs: 60_000 },
        }),
      ),
      req,
    );
    expect(out.status).toBe(503);
    expect(out.nextCalled).toBe(false);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service unavailable' },
    });
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'store_unavailable');
  });

  it('FIX 3: invalid_config (non-finite ed25519 maxSkewSeconds) -> 503, not 401', async () => {
    const onFailure = vi.fn();
    const keyPair = generateKeyPairSync('ed25519');
    const publicKeyHex = keyPair.publicKey
      .export({ type: 'spki', format: 'der' })
      .subarray(12)
      .toString('hex');
    const ts = String(Math.floor(Date.now() / 1000));
    const body = '{"type":1}';
    const message = Buffer.concat([Buffer.from(ts, 'utf8'), Buffer.from(body, 'utf8')]);
    const signatureHex = cryptoSign(null, message, keyPair.privateKey).toString('hex');
    const req = makeReq({
      headers: { 'x-signature-ed25519': signatureHex, 'x-signature-timestamp': ts },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier({
        scheme: 'ed25519',
        publicKey: publicKeyHex,
        timestamp: { header: 'x-signature-timestamp', maxSkewSeconds: NaN },
        onFailure,
      } as WebhookVerifierConfig),
      req,
    );
    expect(out.status).toBe(503);
    expect(out.nextCalled).toBe(false);
    expect(out.body).toEqual({
      error: { code: 'SERVICE_UNAVAILABLE', message: 'Service unavailable' },
    });
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'invalid_config');
  });
});

describe('createWebhookVerifier — generic responses never leak the reason', () => {
  it('the specific reason is in onFailure but NEVER in the response body', async () => {
    const onFailure = vi.fn();
    const body = '{"event":"push"}';
    const cases: Array<[Partial<Request>, Partial<WebhookVerifierConfig>]> = [
      [
        { headers: { 'x-hub-signature-256': hmacSign('different body') }, rawBody: body } as Partial<Request>,
        {},
      ],
      [
        { headers: { 'x-hub-signature-256': hmacSign(body) }, rawBody: body } as Partial<Request>,
        { secret: () => undefined },
      ],
    ];
    for (const [reqPartial, over] of cases) {
      const out = await invoke(
        createWebhookVerifier(baseConfig({ onFailure, ...over })),
        makeReq(reqPartial),
      );
      const bodyStr = JSON.stringify(out.body);
      expect(bodyStr).not.toMatch(/bad_signature|missing_secret|reason/i);
    }
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'bad_signature');
    expect(onFailure).toHaveBeenCalledWith(expect.anything(), 'missing_secret');
  });

  it('a throwing onFailure hook does not change the 401 or crash', async () => {
    const warn = vi.fn();
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign('different body') },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier(
        baseConfig({
          logger: { warn },
          onFailure: () => {
            throw new Error('audit boom');
          },
        }),
      ),
      req,
    );
    expect(out.status).toBe(401);
    expect(out.nextCalled).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it('a throwing onFailure hook does not change the 503 or crash', async () => {
    const warn = vi.fn();
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign(body) },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier(
        baseConfig({
          secret: () => undefined,
          logger: { warn },
          onFailure: () => {
            throw new Error('audit boom');
          },
        }),
      ),
      req,
    );
    expect(out.status).toBe(503);
    expect(out.nextCalled).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it('an async onFailure rejection does not break the response', async () => {
    const warn = vi.fn();
    const body = '{"event":"push"}';
    const req = makeReq({
      headers: { 'x-hub-signature-256': hmacSign('different body') },
      rawBody: body,
    } as Partial<Request>);
    const out = await invoke(
      createWebhookVerifier(
        baseConfig({
          logger: { warn },
          onFailure: () => Promise.reject(new Error('async audit boom')),
        }),
      ),
      req,
    );
    expect(out.status).toBe(401);
    await Promise.resolve();
    await Promise.resolve();
    expect(warn).toHaveBeenCalled();
  });
});
