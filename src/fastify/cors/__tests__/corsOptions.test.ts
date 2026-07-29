import { describe, it, expect, vi } from 'vitest';
import { corsOptions } from '../corsOptions';
import type { CorsOptionsConfig } from '../corsOptions';

/** Invoke the resolved `origin` callback option and capture the (err, allowed) result. */
function invokeOrigin(
  opts: ReturnType<typeof corsOptions>,
  origin: string | undefined,
): { err: unknown; allowed: unknown } {
  let captured: { err: unknown; allowed: unknown } | undefined;
  opts.origin(origin, (err, allowed) => {
    captured = { err, allowed };
  });
  if (!captured) {
    throw new Error('origin callback did not call back synchronously');
  }
  return captured;
}

function baseConfig(over: Partial<CorsOptionsConfig> = {}): CorsOptionsConfig {
  return {
    env: 'production',
    origins: ['https://app.example.com'],
    ...over,
  };
}

describe('fastify corsOptions — origin callback', () => {
  it('allowed origin → callback(null, <canonical string>), NOT callback(null, true)', () => {
    // `callback(null, true)` would make `@fastify/cors` REFLECT the raw
    // request Origin header verbatim. The canonical string is the fixed,
    // policy-authorized value instead of attacker-controlled request bytes.
    const opts = corsOptions(baseConfig());
    const { err, allowed } = invokeOrigin(opts, 'https://app.example.com');
    expect(err).toBeNull();
    expect(allowed).toBe('https://app.example.com');
    expect(allowed).not.toBe(true);
  });

  it('for an allowed origin, the callback is invoked with the CANONICAL string, never `true`, even for a non-canonical (but matching) raw input', () => {
    const opts = corsOptions(baseConfig({ origins: ['https://App.Example.com:443'] }));
    const { allowed } = invokeOrigin(opts, 'https://APP.EXAMPLE.COM:443/some/path?x=1');
    expect(allowed).toBe('https://app.example.com');
    expect(allowed).not.toBe(true);
  });

  it('denied origin → callback(null, false), and onReject fired', () => {
    const onReject = vi.fn();
    const opts = corsOptions(baseConfig({ onReject }));
    const { err, allowed } = invokeOrigin(opts, 'https://evil.com');
    expect(err).toBeNull();
    expect(allowed).toBe(false);
    expect(onReject).toHaveBeenCalledWith('https://evil.com');
  });

  it('never reflects the incoming (denied) origin string back as the allowed value', () => {
    const opts = corsOptions(baseConfig());
    const attacker = 'https://attacker-' + Math.random().toString(36).slice(2) + '.com';
    const { allowed } = invokeOrigin(opts, attacker);
    expect(allowed).not.toBe(attacker);
    expect(allowed).toBe(false);
  });

  it('undefined origin (no-Origin request) is governed by allowNoOrigin default (true)', () => {
    const opts = corsOptions(baseConfig());
    const { allowed } = invokeOrigin(opts, undefined);
    expect(allowed).toBe(true);
  });
});

describe('fastify corsOptions — prod-empty throws at construction', () => {
  it('throws synchronously when called with production + no origins — fails closed at BOOT, not on the first request', () => {
    expect(() => corsOptions({ env: 'production' })).toThrow();
  });

  it('resolves the policy ONCE at construction — does not throw when origins are configured', () => {
    expect(() =>
      corsOptions({ env: 'production', origins: ['https://app.example.com'] }),
    ).not.toThrow();
  });
});

describe('fastify corsOptions — overridable NON-security defaults', () => {
  it('applies the documented defaults when not overridden', () => {
    const opts = corsOptions(baseConfig());
    expect(opts.credentials).toBe(true);
    expect(opts.methods).toEqual(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']);
    expect(opts.allowedHeaders).toEqual(
      expect.arrayContaining([
        'Content-Type',
        'Authorization',
        'X-Bot-Key-Id',
        'X-Timestamp',
        'X-Nonce',
        'X-Signature',
        'X-Request-Id',
      ]),
    );
    expect(opts.exposedHeaders).toEqual([
      'RateLimit-Limit',
      'RateLimit-Remaining',
      'RateLimit-Reset',
    ]);
    expect(opts.optionsSuccessStatus).toBe(200);
    expect(opts.maxAge).toBe(86400);
  });

  it('lets the consumer override credentials/methods/headers/maxAge/status', () => {
    const opts = corsOptions(
      baseConfig({
        credentials: false,
        methods: ['GET'],
        allowedHeaders: ['X-Custom'],
        exposedHeaders: ['X-Custom-Exposed'],
        optionsSuccessStatus: 204,
        maxAge: 3600,
      }),
    );
    expect(opts.credentials).toBe(false);
    expect(opts.methods).toEqual(['GET']);
    expect(opts.allowedHeaders).toEqual(['X-Custom']);
    expect(opts.exposedHeaders).toEqual(['X-Custom-Exposed']);
    expect(opts.optionsSuccessStatus).toBe(204);
    expect(opts.maxAge).toBe(3600);
  });
});

describe('fastify corsOptions — the origin callback cannot be overridden by the consumer', () => {
  it('CorsOptionsConfig has no `origin` field — a config object cannot supply one that survives', () => {
    const maliciousConfig = {
      ...baseConfig(),
      origin: (_o: unknown, cb: (err: unknown, allowed?: unknown) => void) => cb(null, true),
    } as CorsOptionsConfig;

    const opts = corsOptions(maliciousConfig);
    const { allowed } = invokeOrigin(opts, 'https://evil.com');
    // Still denied — the smuggled `origin` field was never wired in.
    expect(allowed).toBe(false);
  });
});
