import { describe, expect, test } from 'vitest';
import fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import { corsOptions } from '../corsOptions';

/**
 * The sibling unit test invokes the `origin` callback directly, which proves
 * what the callback RETURNS but not what `@fastify/cors` then DOES with it.
 * The security claim is about the emitted header — that an allowed origin
 * yields the fixed canonical allowlist value and never a reflection of
 * attacker-controlled request bytes — so it has to be asserted against a real
 * plugin-mounted response.
 *
 * Concretely: `callback(null, true)` would make the plugin echo the raw
 * incoming `Origin` header back into `Access-Control-Allow-Origin`. These
 * tests fail if the adapter ever regresses to that.
 */
async function buildApp(config: Parameters<typeof corsOptions>[0]) {
  const app = fastify();
  await app.register(fastifyCors, corsOptions(config));
  app.get('/thing', async () => ({ ok: true }));
  await app.ready();
  return app;
}

const ORIGINS = ['https://app.example.com'];

describe('corsOptions + @fastify/cors (integration)', () => {
  test('an allowed origin gets the exact canonical allowlist value', async () => {
    const app = await buildApp({ env: 'production', origins: ORIGINS });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/thing',
        headers: { origin: 'https://app.example.com' },
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
    } finally {
      await app.close();
    }
  });

  test('a NON-canonical but matching origin still gets the canonical value back, not its own bytes', async () => {
    // `https://app.example.com:443` normalizes to the allowlisted origin (443
    // is https's default port). It must be ALLOWED, but the response must
    // carry the stored canonical form — echoing the caller's spelling back is
    // the reflection bug, even when the caller is legitimate.
    const app = await buildApp({ env: 'production', origins: ORIGINS });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/thing',
        headers: { origin: 'https://app.example.com:443' },
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
    } finally {
      await app.close();
    }
  });

  test('a denied origin gets NO Access-Control-Allow-Origin header at all', async () => {
    const app = await buildApp({ env: 'production', origins: ORIGINS });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/thing',
        headers: { origin: 'https://evil.example.com' },
      });

      // The request itself still runs — CORS is enforced by the BROWSER, and
      // the kit's job is to withhold the grant, not to fail the request.
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      expect(res.headers['access-control-allow-origin']).not.toBe('https://evil.example.com');
    } finally {
      await app.close();
    }
  });

  test('a preflight from an allowed origin is granted with the canonical value', async () => {
    const app = await buildApp({ env: 'production', origins: ORIGINS });
    try {
      const res = await app.inject({
        method: 'OPTIONS',
        url: '/thing',
        headers: {
          origin: 'https://app.example.com',
          'access-control-request-method': 'POST',
        },
      });

      expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
      expect(String(res.headers['access-control-allow-methods'])).toContain('POST');
    } finally {
      await app.close();
    }
  });

  test('a preflight from a denied origin is not granted', async () => {
    const app = await buildApp({ env: 'production', origins: ORIGINS });
    try {
      const res = await app.inject({
        method: 'OPTIONS',
        url: '/thing',
        headers: {
          origin: 'https://evil.example.com',
          'access-control-request-method': 'POST',
        },
      });

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  test('an empty production allowlist fails closed at construction, before any request', async () => {
    expect(() => corsOptions({ env: 'production', origins: [] })).toThrow();
  });
});
