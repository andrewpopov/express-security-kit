import { describe, it, expect, afterEach, vi } from 'vitest';
import fastify, { FastifyInstance } from 'fastify';
import { createRateLimiter, FastifyRateLimiterConfig } from '../createRateLimiter';
import { MemoryRateLimitStore, RateLimitStore } from '../../../core/rate-limit/store';

/**
 * Real integration tests: a `fastify()` app with `createRateLimiter` mounted
 * as a `preHandler` and driven via `app.inject()` — not mocks. A bug in this
 * file is exactly a bug in how the core's outcome reaches the wire (headers,
 * status, body, and whether the route handler actually runs).
 */

const stores: MemoryRateLimitStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryRateLimitStore>) {
  const s = new MemoryRateLimitStore(...args);
  stores.push(s);
  return s;
}
afterEach(() => {
  while (stores.length) stores.pop()!.dispose();
});

const apps: FastifyInstance[] = [];
afterEach(async () => {
  while (apps.length) await apps.pop()!.close();
});

/** Build an app with the limiter mounted as a preHandler in front of `/thing`. */
async function buildApp(
  config: FastifyRateLimiterConfig | FastifyRateLimiterConfig[],
  onHandlerHit?: () => void,
): Promise<FastifyInstance> {
  const app = fastify();
  apps.push(app);
  app.get(
    '/thing',
    { preHandler: createRateLimiter(config) },
    async () => {
      onHandlerHit?.();
      return { ok: true };
    },
  );
  await app.ready();
  return app;
}

describe('createRateLimiter (Fastify, integration)', () => {
  it('under the limit: 200 with RateLimit-* headers present', async () => {
    const store = makeStore();
    const app = await buildApp({ windowMs: 5000, max: 5, store, now: () => 10_000 });

    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['ratelimit-limit']).toBe('5');
    expect(res.headers['ratelimit-remaining']).toBe('4');
    expect(res.headers['ratelimit-reset']).toBeDefined();
  });

  it('over the limit: 429, the default body shape, and Retry-After', async () => {
    const store = makeStore();
    const app = await buildApp({ windowMs: 5000, max: 1, store, now: () => 10_000 });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: expect.any(String),
        retryAfter: expect.any(Number),
      },
    });
    expect(res.headers['retry-after']).toBeDefined();
    expect(res.headers['content-type']).toMatch(/^application\/json/);
  });

  it('the route handler is NOT reached on a 429', async () => {
    const store = makeStore();
    let handlerReached = false;
    const app = await buildApp(
      { windowMs: 5000, max: 1, store, now: () => 10_000 },
      () => {
        handlerReached = true;
      },
    );

    await app.inject({ method: 'GET', url: '/thing' });
    handlerReached = false; // reset after the allowed first request
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(handlerReached).toBe(false);
  });

  it('headers: false emits none of the four headers', async () => {
    const store = makeStore();
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      headers: false,
      store,
      now: () => 10_000,
    });

    const allowed = await app.inject({ method: 'GET', url: '/thing' }); // 200
    const rejected = await app.inject({ method: 'GET', url: '/thing' }); // 429

    expect(allowed.statusCode).toBe(200);
    expect(rejected.statusCode).toBe(429);
    for (const r of [allowed, rejected]) {
      expect(r.headers['ratelimit-limit']).toBeUndefined();
      expect(r.headers['ratelimit-remaining']).toBeUndefined();
      expect(r.headers['ratelimit-reset']).toBeUndefined();
      expect(r.headers['retry-after']).toBeUndefined();
    }
  });

  it('a tier array where the FIRST tier rejects records no hit on the second tier', async () => {
    const storeA = makeStore();
    const storeB = makeStore();
    const hitSpyB = vi.spyOn(storeB, 'hit');
    const app = await buildApp([
      { windowMs: 5000, max: 1, store: storeA, now: () => 10_000 },
      { windowMs: 5000, max: 100, store: storeB, now: () => 10_000 },
    ]);

    await app.inject({ method: 'GET', url: '/thing' }); // trips tier A to its limit
    hitSpyB.mockClear();
    const res = await app.inject({ method: 'GET', url: '/thing' }); // tier A rejects

    expect(res.statusCode).toBe(429);
    expect(hitSpyB).not.toHaveBeenCalled();
  });

  it('skip: () => true passes through with no headers and no store hit', async () => {
    const store = makeStore();
    const hitSpy = vi.spyOn(store, 'hit');
    let handlerReached = false;
    const app = await buildApp(
      { windowMs: 5000, max: 1, skip: () => true, store, now: () => 10_000 },
      () => {
        handlerReached = true;
      },
    );

    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(200);
    expect(handlerReached).toBe(true);
    expect(hitSpy).not.toHaveBeenCalled();
    expect(res.headers['ratelimit-limit']).toBeUndefined();
  });

  it('a throwing store.hit FAILS OPEN: 200, handler reached', async () => {
    const throwingStore: RateLimitStore = {
      hit: () => {
        throw new Error('store outage');
      },
      reset: () => Promise.resolve(),
      decrement: () => Promise.resolve(),
    };
    let handlerReached = false;
    const app = await buildApp(
      { windowMs: 5000, max: 1, store: throwingStore, now: () => 10_000 },
      () => {
        handlerReached = true;
      },
    );

    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(200);
    expect(handlerReached).toBe(true);
  });

  it('skipSuccessful refunds a 200 response, so it does not consume the limit', async () => {
    const store = makeStore();
    const app = fastify();
    apps.push(app);
    app.get(
      '/ok',
      { preHandler: createRateLimiter({ windowMs: 5000, max: 1, skipSuccessful: true, store, now: () => 10_000 }) },
      async () => ({ ok: true }),
    );
    await app.ready();

    // Same store/window/key under max: 1. Without the refund the second
    // request would be the second counted hit and get a 429 — so this passing
    // twice is exactly the evidence that the `finish` refund fired.
    const okRes = await app.inject({ method: 'GET', url: '/ok' });
    expect(okRes.statusCode).toBe(200);
    const stillOk = await app.inject({ method: 'GET', url: '/ok' });
    expect(stillOk.statusCode).toBe(200);
  });

  it('skipSuccessful does not refund a 400+ response, so it counts toward the limit', async () => {
    const store = makeStore();
    const app = fastify();
    apps.push(app);
    app.get(
      '/fail',
      { preHandler: createRateLimiter({ windowMs: 5000, max: 1, skipSuccessful: true, store, now: () => 10_000 }) },
      async (_req, reply) => reply.code(400).send({ ok: false }),
    );
    await app.ready();

    const first = await app.inject({ method: 'GET', url: '/fail' });
    expect(first.statusCode).toBe(400);
    const second = await app.inject({ method: 'GET', url: '/fail' });
    expect(second.statusCode).toBe(429); // not refunded, so the limit is now closed
  });

  it('buildResponseBody replaces the 429 body', async () => {
    const store = makeStore();
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      store,
      now: () => 10_000,
      buildResponseBody: () => ({ custom: true }),
    });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({ custom: true });
  });

  it('a primitive custom body matches Express byte-for-byte', async () => {
    const store = makeStore();
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      store,
      now: () => 10_000,
      buildResponseBody: () => 'limited',
    });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.headers['content-type']).toMatch(/^application\/json/);
    expect(res.body).toBe('"limited"');
  });

  it('an array custom body is emitted as JSON too', async () => {
    const store = makeStore();
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      store,
      now: () => 10_000,
      buildResponseBody: () => [1, 2],
    });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.headers['content-type']).toMatch(/^application\/json/);
    expect(res.body).toBe('[1,2]');
  });

  it('a decided rejection does NOT fail open when response I/O throws', async () => {
    const store = makeStore();
    let handlerReached = false;
    const app = fastify();
    apps.push(app);
    app.get(
      '/thing',
      {
        preHandler: [
          async (_request, reply) => {
            reply.header = () => {
              throw new Error('response I/O boom');
            };
          },
          createRateLimiter({ windowMs: 5000, max: 1, store, now: () => 10_000 }),
        ],
      },
      async () => {
        handlerReached = true;
        return { ok: true };
      },
    );
    await app.ready();

    await app.inject({ method: 'GET', url: '/thing' }); // trips the limit
    handlerReached = false; // reset after the allowed first request
    const res = await app.inject({ method: 'GET', url: '/thing' }); // over limit

    expect(handlerReached).toBe(false);
    expect(res.statusCode).toBe(500);
  });

  it('the allow path still fails open when header emission throws', async () => {
    const store = makeStore();
    let handlerReached = false;
    const app = fastify();
    apps.push(app);
    app.get(
      '/thing',
      {
        preHandler: [
          async (_request, reply) => {
            reply.header = () => {
              throw new Error('response I/O boom');
            };
          },
          createRateLimiter({ windowMs: 5000, max: 5, store, now: () => 10_000 }),
        ],
      },
      async () => {
        handlerReached = true;
        return { ok: true };
      },
    );
    await app.ready();

    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(handlerReached).toBe(true);
    expect(res.statusCode).toBe(200);
  });

  it('a throwing onLimit AND a throwing logger still yields 429, route handler not reached', async () => {
    const store = makeStore();
    let handlerReached = false;
    const throwingLogger = {
      warn: () => {
        throw new Error('logger boom');
      },
    };
    const app = await buildApp(
      {
        windowMs: 5000,
        max: 1,
        store,
        now: () => 10_000,
        logger: throwingLogger,
        onLimit: () => {
          throw new Error('onLimit boom');
        },
      },
      () => {
        handlerReached = true;
      },
    );

    await app.inject({ method: 'GET', url: '/thing' }); // trips the limit
    handlerReached = false; // reset after the allowed first request
    const res = await app.inject({ method: 'GET', url: '/thing' }); // over limit

    expect(res.statusCode).toBe(429);
    expect(handlerReached).toBe(false);
  });

  it('a function buildResponseBody falls back to the default envelope, not an empty body', async () => {
    const store = makeStore();
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      store,
      now: () => 10_000,
      buildResponseBody: () => () => {},
    });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: expect.any(String),
        retryAfter: expect.any(Number),
      },
    });
  });

  it('a toJSON() returning undefined falls back to the default envelope, not an empty body', async () => {
    const store = makeStore();
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      store,
      now: () => 10_000,
      buildResponseBody: () => ({ toJSON: () => undefined }),
    });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: expect.any(String),
        retryAfter: expect.any(Number),
      },
    });
  });

  it('a toJSON() that succeeds once then throws still produces a correct 429 (serialized exactly once)', async () => {
    const store = makeStore();
    let toJSONCalls = 0;
    const app = await buildApp({
      windowMs: 5000,
      max: 1,
      store,
      now: () => 10_000,
      buildResponseBody: () => ({
        toJSON: () => {
          toJSONCalls += 1;
          if (toJSONCalls > 1) {
            throw new Error('second serialization boom');
          }
          return { custom: true };
        },
      }),
    });

    await app.inject({ method: 'GET', url: '/thing' });
    const res = await app.inject({ method: 'GET', url: '/thing' });

    expect(res.statusCode).toBe(429);
    expect(res.json()).toEqual({ custom: true });
    expect(toJSONCalls).toBe(1);
  });

  it('honors the per-request override via request.securityContext.rateLimitOverride', async () => {
    const store = makeStore();
    const app = fastify();
    apps.push(app);
    app.get(
      '/thing',
      {
        preHandler: [
          async (request) => {
            request.securityContext = {
              principalType: 'anonymous',
              rateLimitOverride: { windowMs: 5000, max: 100 },
            };
          },
          createRateLimiter({ windowMs: 5000, max: 1, store, now: () => 10_000 }),
        ],
      },
      async () => ({ ok: true }),
    );
    await app.ready();

    // The base config's max: 1 would reject the second request, but the
    // override (max: 100) set in an earlier preHandler takes effect instead.
    const first = await app.inject({ method: 'GET', url: '/thing' });
    const second = await app.inject({ method: 'GET', url: '/thing' });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
  });
});
