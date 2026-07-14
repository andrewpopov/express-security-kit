import { describe, it, expect, vi, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { Request } from 'express';
import { createRateLimiter, RateLimiterConfig } from '../createRateLimiter';
import { MemoryRateLimitStore, RateLimitStore } from '../../../core/rate-limit/store';
import { ipKey } from '../../../core/rate-limit/keyGenerator';
import { RedisRateLimitStore, RedisLikeClient } from '../../../core/rate-limit/redis-store';

const stores: MemoryRateLimitStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryRateLimitStore>) {
  const s = new MemoryRateLimitStore(...args);
  stores.push(s);
  return s;
}
afterEach(() => {
  while (stores.length) stores.pop()!.stop();
});

interface FakeResult {
  status?: number;
  body?: unknown;
  headers: Record<string, string>;
  nextCalled: boolean;
}

function makeRes(onDone: () => void): { res: any; result: FakeResult } {
  const result: FakeResult = { headers: {}, nextCalled: false };
  const res: any = {
    headersSent: false,
    setHeader(name: string, value: string) {
      result.headers[name] = String(value);
    },
    status(code: number) {
      result.status = code;
      return res;
    },
    json(payload: unknown) {
      result.body = payload;
      res.headersSent = true;
      onDone(); // request rejected — settle the invoke() promise
      return res;
    },
  };
  return { res, result };
}

function makeReq(partial: Partial<Request> = {}): Request {
  return { headers: {}, ip: '1.2.3.4', ...partial } as Request;
}

/** Run a limiter once, returning what happened. */
async function invoke(
  mw: ReturnType<typeof createRateLimiter>,
  req: Request,
): Promise<FakeResult> {
  let result!: FakeResult;
  await new Promise<void>((resolve) => {
    const made = makeRes(resolve);
    result = made.result;
    mw(req, made.res, () => {
      result.nextCalled = true;
      resolve();
    });
  });
  return result;
}

describe('fixed window', () => {
  it('allows up to max then rejects with 429', async () => {
    const store = makeStore();
    const now = 10_000;
    const mw = createRateLimiter({ windowMs: 1000, max: 2, store, now: () => now });
    const r = makeReq();
    expect((await invoke(mw, r)).nextCalled).toBe(true); // 1
    expect((await invoke(mw, r)).nextCalled).toBe(true); // 2
    const third = await invoke(mw, r);
    expect(third.nextCalled).toBe(false);
    expect(third.status).toBe(429);
    expect(third.body).toMatchObject({ error: { code: 'RATE_LIMITED' } });
  });

  it('resets on the next window', async () => {
    const store = makeStore();
    let now = 10_000;
    const mw = createRateLimiter({ windowMs: 1000, max: 1, store, now: () => now });
    const r = makeReq();
    expect((await invoke(mw, r)).nextCalled).toBe(true);
    expect((await invoke(mw, r)).nextCalled).toBe(false); // blocked
    now = 11_000; // new window
    expect((await invoke(mw, r)).nextCalled).toBe(true); // allowed again
  });

  it('emits RateLimit-* headers on allow', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 1000, max: 5, store, now: () => 10_000 });
    const res = await invoke(mw, makeReq());
    expect(res.headers['RateLimit-Limit']).toBe('5');
    expect(res.headers['RateLimit-Remaining']).toBe('4');
    expect(res.headers['RateLimit-Reset']).toBe('1'); // 1000ms -> 1s
  });

  it('emits Retry-After on 429', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 2000, max: 1, store, now: () => 10_000 });
    const r = makeReq();
    await invoke(mw, r);
    const blocked = await invoke(mw, r);
    expect(blocked.status).toBe(429);
    expect(blocked.headers['Retry-After']).toBe('2');
    expect(blocked.headers['RateLimit-Remaining']).toBe('0');
  });

  it('omits headers when headers:false', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 1000, max: 5, store, headers: false, now: () => 10_000 });
    const res = await invoke(mw, makeReq());
    expect(res.headers['RateLimit-Limit']).toBeUndefined();
  });
});

describe('sliding window', () => {
  it('allows exactly max in an empty window, same as fixed', async () => {
    const store = makeStore();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 3,
      algorithm: 'sliding',
      keyGenerator: ipKey,
      store,
      now: () => 10_000, // fresh window, no previous-window carryover
    });
    const r = makeReq();
    expect((await invoke(mw, r)).nextCalled).toBe(true); // weighted 1 <= 3
    expect((await invoke(mw, r)).nextCalled).toBe(true); // weighted 2 <= 3
    expect((await invoke(mw, r)).nextCalled).toBe(true); // weighted 3 <= 3
    const fourth = await invoke(mw, r); // weighted 4 > 3
    expect(fourth.nextCalled).toBe(false);
    expect(fourth.status).toBe(429);
  });

  it('carries weighted load from the previous window (sliding-specific)', async () => {
    const windowMs = 1000;
    const max = 10;

    // Seed the previous window (index 1) at capacity: 10 hits.
    const seed = () => {
      const store = makeStore();
      for (let i = 0; i < 10; i++) void store.hit('ip:1.2.3.4', windowMs, 1000);
      return store;
    };

    // At the very START of the new window (now=2000) the previous window is
    // weighted ~1.0, so weighted ~= 10 + 1 > 10 -> reject. A fixed window would
    // have allowed this request; the carryover is the sliding-specific effect.
    const early = await invoke(
      createRateLimiter({ windowMs, max, algorithm: 'sliding', keyGenerator: ipKey, store: seed(), now: () => 2000 }),
      makeReq(),
    );
    expect(early.nextCalled).toBe(false);
    expect(early.status).toBe(429);

    // Near the END of the window (now=2950) the previous window's weight decays
    // to ~0.05, so weighted ~= 0.5 + 1 <= 10 -> allowed again.
    const late = await invoke(
      createRateLimiter({ windowMs, max, algorithm: 'sliding', keyGenerator: ipKey, store: seed(), now: () => 2950 }),
      makeReq(),
    );
    expect(late.nextCalled).toBe(true);
  });
});

describe('keying precedence', () => {
  it('keys separately by principalId vs ip', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 1000, max: 1, store, now: () => 10_000 });
    const userReq = makeReq({ securityContext: { principalType: 'user', principalId: 'u1' } });
    const ipReq = makeReq();
    expect((await invoke(mw, userReq)).nextCalled).toBe(true);
    // Different bucket (ip) still has budget.
    expect((await invoke(mw, ipReq)).nextCalled).toBe(true);
    // Same user bucket is now exhausted.
    expect((await invoke(mw, userReq)).nextCalled).toBe(false);
  });
});

describe('role-aware max', () => {
  it('applies a max function per request', async () => {
    const store = makeStore();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: (req) => (req.securityContext?.principalType === 'service' ? 3 : 1),
      store,
      now: () => 10_000,
    });
    const svc = makeReq({ securityContext: { principalType: 'service', principalId: 's1' } });
    expect((await invoke(mw, svc)).nextCalled).toBe(true);
    expect((await invoke(mw, svc)).nextCalled).toBe(true);
    expect((await invoke(mw, svc)).nextCalled).toBe(true);
    expect((await invoke(mw, svc)).nextCalled).toBe(false); // 4th blocked at max 3
  });
});

describe('overrideResolver', () => {
  it('reads rateLimitOverride from securityContext by default', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 1000, max: 1, store, now: () => 10_000 });
    const req = makeReq({
      securityContext: {
        principalType: 'apiKey',
        principalId: 'k1',
        rateLimitOverride: { windowMs: 1000, max: 2 },
      },
    });
    expect((await invoke(mw, req)).nextCalled).toBe(true);
    expect((await invoke(mw, req)).nextCalled).toBe(true); // override raises to 2
    expect((await invoke(mw, req)).nextCalled).toBe(false);
  });

  it('honors a custom overrideResolver', async () => {
    const store = makeStore();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 1,
      store,
      now: () => 10_000,
      overrideResolver: () => ({ windowMs: 1000, max: 5 }),
    });
    const req = makeReq();
    for (let i = 0; i < 5; i++) expect((await invoke(mw, req)).nextCalled).toBe(true);
    expect((await invoke(mw, req)).nextCalled).toBe(false);
  });
});

describe('skip and onLimit', () => {
  it('skips limiting entirely', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 1000, max: 1, store, skip: () => true, now: () => 10_000 });
    const r = makeReq();
    for (let i = 0; i < 5; i++) expect((await invoke(mw, r)).nextCalled).toBe(true);
  });

  it('invokes onLimit with req and key on rejection', async () => {
    const store = makeStore();
    const onLimit = vi.fn();
    const mw = createRateLimiter({ windowMs: 1000, max: 1, store, onLimit, now: () => 10_000 });
    const r = makeReq();
    await invoke(mw, r);
    await invoke(mw, r);
    expect(onLimit).toHaveBeenCalledOnce();
    expect(onLimit.mock.calls[0][1]).toBe('ip:1.2.3.4');
  });

  it('still returns 429 when onLimit throws synchronously', async () => {
    const store = makeStore();
    const warn = vi.fn();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 1,
      store,
      logger: { warn },
      now: () => 10_000,
      onLimit: () => {
        throw new Error('hook boom');
      },
    });
    const r = makeReq();
    await invoke(mw, r);
    const blocked = await invoke(mw, r);
    expect(blocked.nextCalled).toBe(false); // NOT converted into an allow
    expect(blocked.status).toBe(429);
    expect(warn).toHaveBeenCalled();
  });

  it('still returns 429 when an async onLimit rejects', async () => {
    const store = makeStore();
    const warn = vi.fn();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 1,
      store,
      logger: { warn },
      now: () => 10_000,
      onLimit: () => Promise.reject(new Error('async hook boom')),
    });
    const r = makeReq();
    await invoke(mw, r);
    const blocked = await invoke(mw, r);
    expect(blocked.status).toBe(429);
    // Give the rejection handler a tick to log.
    await Promise.resolve();
    expect(warn).toHaveBeenCalled();
  });
});

describe('custom 429 response body', () => {
  /** Exhaust a max:1 limiter and return the rejected response. */
  async function reject(overrides: Partial<RateLimiterConfig>): Promise<FakeResult> {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 2000, max: 1, store, now: () => 10_000, ...overrides });
    const r = makeReq();
    await invoke(mw, r); // consume the single allowance
    return invoke(mw, r); // this one is rejected
  }

  it('default body is byte-unchanged when neither option is set', async () => {
    const res = await reject({});
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please retry later.',
        retryAfter: 2, // 2000ms window
      },
    });
  });

  it('message overrides only the message text; code + shape unchanged', async () => {
    const res = await reject({ message: 'Slow down!' });
    expect(res.body).toEqual({
      error: { code: 'RATE_LIMITED', message: 'Slow down!', retryAfter: 2 },
    });
  });

  it('buildResponseBody fully replaces the envelope; headers + 429 still present', async () => {
    const res = await reject({
      buildResponseBody: () => ({ error: 'Too many requests' }),
    });
    expect(res.status).toBe(429);
    expect(res.body).toEqual({ error: 'Too many requests' });
    // default envelope is NOT used
    expect(res.body).not.toHaveProperty('error.code');
    expect(res.headers['RateLimit-Limit']).toBe('1');
    expect(res.headers['Retry-After']).toBe('2');
  });

  it('buildResponseBody receives correct rejection info', async () => {
    let seen: any;
    await reject({
      keyGenerator: ipKey,
      buildResponseBody: (info) => {
        seen = info;
        return { error: 'nope' };
      },
    });
    expect(seen).toMatchObject({
      limit: 1,
      remaining: 0,
      resetAt: 12_000,
      retryAfterSeconds: 2,
      key: 'ip:1.2.3.4',
    });
    expect(seen.req).toBeDefined();
  });

  it('a throwing buildResponseBody falls back to the default body + logs', async () => {
    const warn = vi.fn();
    const res = await reject({
      logger: { warn },
      buildResponseBody: () => {
        throw new Error('formatter boom');
      },
    });
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please retry later.',
        retryAfter: 2,
      },
    });
    expect(warn).toHaveBeenCalled();
  });

  it('a throwing buildResponseBody falls back honoring message', async () => {
    const res = await reject({
      logger: { warn: vi.fn() },
      message: 'Custom fallback',
      buildResponseBody: () => {
        throw new Error('boom');
      },
    });
    expect(res.body).toEqual({
      error: { code: 'RATE_LIMITED', message: 'Custom fallback', retryAfter: 2 },
    });
  });

  it('a nullish buildResponseBody return falls back to the default body (not empty)', async () => {
    const res = await reject({
      buildResponseBody: () => undefined,
    });
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please retry later.',
        retryAfter: 2,
      },
    });
  });

  it('an async buildResponseBody is rejected and falls back to the default body', async () => {
    const warn = vi.fn();
    const res = await reject({
      logger: { warn },
      // eslint-disable-next-line @typescript-eslint/require-await
      buildResponseBody: async () => ({ error: 'nope' }),
    });
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please retry later.',
        retryAfter: 2,
      },
    });
    expect(warn).toHaveBeenCalled();
  });

  it('a non-JSON-serializable buildResponseBody return falls back to the default body', async () => {
    const warn = vi.fn();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const res = await reject({
      logger: { warn },
      buildResponseBody: () => circular,
    });
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please retry later.',
        retryAfter: 2,
      },
    });
    expect(warn).toHaveBeenCalled();
  });

  it('a throwing logger does not prevent the default body on a bad formatter', async () => {
    const res = await reject({
      logger: {
        warn: () => {
          throw new Error('logger boom');
        },
      },
      buildResponseBody: () => {
        throw new Error('formatter boom');
      },
    });
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please retry later.',
        retryAfter: 2,
      },
    });
  });
});

describe('fail-open', () => {
  it('allows the request when the store throws', async () => {
    const throwingStore: RateLimitStore = {
      hit: () => Promise.reject(new Error('redis down')),
      reset: () => Promise.resolve(),
      decrement: () => Promise.resolve(),
    };
    const warn = vi.fn();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 1,
      store: throwingStore,
      logger: { warn },
      now: () => 10_000,
    });
    const res = await invoke(mw, makeReq());
    expect(res.nextCalled).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('allows the request when RedisRateLimitStore.hit rejects (eval throws)', async () => {
    const rejectingEvalClient: RedisLikeClient = {
      incr: async () => 1,
      decr: async () => 0,
      pexpire: async () => 1,
      get: async () => null,
      del: async () => 0,
      eval: () => Promise.reject(new Error('eval failed')),
    };
    const warn = vi.fn();
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 1,
      store: new RedisRateLimitStore(rejectingEvalClient),
      logger: { warn },
      now: () => 10_000,
    });
    const res = await invoke(mw, makeReq());
    expect(res.nextCalled).toBe(true);
    expect(warn).toHaveBeenCalled();
  });
});

describe('dual-tier', () => {
  function tiers(): RateLimiterConfig[] {
    return [
      { windowMs: 1000, max: 5, keyGenerator: (r) => `key:${r.securityContext?.keyId}`, store: makeStore(), now: () => 10_000 },
      { windowMs: 1000, max: 2, keyGenerator: ipKey, store: makeStore(), now: () => 10_000 },
    ];
  }

  it('enforces both tiers; the first to exceed wins', async () => {
    const mw = createRateLimiter(tiers());
    const req = makeReq({ securityContext: { principalType: 'apiKey', keyId: 'kid' } });
    // per-IP tier (max 2) is stricter and trips first at the 3rd request.
    expect((await invoke(mw, req)).nextCalled).toBe(true);
    expect((await invoke(mw, req)).nextCalled).toBe(true);
    const third = await invoke(mw, req);
    expect(third.nextCalled).toBe(false);
    expect(third.status).toBe(429);
  });

  it('trips the per-key tier when it is the stricter one', async () => {
    const mw = createRateLimiter([
      { windowMs: 1000, max: 1, keyGenerator: (r) => `key:${r.securityContext?.keyId}`, store: makeStore(), now: () => 10_000 },
      { windowMs: 1000, max: 100, keyGenerator: ipKey, store: makeStore(), now: () => 10_000 },
    ]);
    const req = makeReq({ securityContext: { principalType: 'apiKey', keyId: 'kid' } });
    expect((await invoke(mw, req)).nextCalled).toBe(true);
    expect((await invoke(mw, req)).nextCalled).toBe(false); // per-key tier trips
  });
});

describe('skipSuccessful (refund on success)', () => {
  /** A res that is an EventEmitter so the limiter can hook finish/close. */
  function makeEventRes(onDone: () => void): any {
    const res: any = new EventEmitter();
    res.statusCode = 200;
    res.headers = {};
    res.headersSent = false;
    res.setHeader = (n: string, v: string) => {
      res.headers[n] = String(v);
    };
    res.status = (c: number) => {
      res.statusCode = c;
      return res;
    };
    res.json = (p: unknown) => {
      res.body = p;
      res.headersSent = true;
      onDone();
      return res;
    };
    return res;
  }

  /**
   * Run the limiter once. If allowed, simulate the route ending with
   * `finalStatus` by setting res.statusCode and emitting 'finish' (which is when
   * the refund fires). Returns whether next() was called + the res.
   */
  async function drive(
    mw: ReturnType<typeof createRateLimiter>,
    req: Request,
    finalStatus = 200,
    endEvent: 'finish' | 'close' = 'finish',
  ): Promise<{ nextCalled: boolean; res: any }> {
    let nextCalled = false;
    const res = await new Promise<any>((resolve) => {
      const r = makeEventRes(() => resolve(r));
      mw(req, r, () => {
        nextCalled = true;
        resolve(r);
      });
    });
    if (nextCalled) {
      res.statusCode = finalStatus;
      res.emit(endEvent);
    }
    return { nextCalled, res };
  }

  it('refunds a successful (<400) request so it does not count', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 5000, max: 1, skipSuccessful: true, store, now: () => 10_000 });
    const r = makeReq();
    // Every request ends 200 and is refunded, so a burst well past max:1 passes.
    for (let i = 0; i < 5; i++) {
      const { nextCalled } = await drive(mw, r, 200);
      expect(nextCalled).toBe(true);
    }
  });

  it('does NOT refund a 4xx or 5xx response (still counts)', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 5000, max: 1, skipSuccessful: true, store, now: () => 10_000 });
    const r = makeReq();
    expect((await drive(mw, r, 500)).nextCalled).toBe(true); // counts (no refund)
    expect((await drive(mw, r, 400)).nextCalled).toBe(false); // blocked
  });

  it('N successes keep a maxed limiter open; N failures then close it', async () => {
    const store = makeStore();
    const mw = createRateLimiter({ windowMs: 5000, max: 3, skipSuccessful: true, store, now: () => 10_000 });
    const r = makeReq();
    // 5 successes — all refunded, limiter never fills.
    for (let i = 0; i < 5; i++) expect((await drive(mw, r, 200)).nextCalled).toBe(true);
    // Now 3 failures fill the window (max 3), the 4th is blocked.
    expect((await drive(mw, r, 500)).nextCalled).toBe(true);
    expect((await drive(mw, r, 500)).nextCalled).toBe(true);
    expect((await drive(mw, r, 500)).nextCalled).toBe(true);
    expect((await drive(mw, r, 500)).nextCalled).toBe(false); // closed
  });

  it('never refunds a rejected (429) request; counter never goes negative', async () => {
    const store = makeStore();
    const decrementSpy = vi.spyOn(store, 'decrement');
    const mw = createRateLimiter({ windowMs: 5000, max: 1, skipSuccessful: true, store, now: () => 10_000 });
    const r = makeReq();
    expect((await drive(mw, r, 500)).nextCalled).toBe(true); // counts, no refund
    // This one is rejected (429). Even if its response emits finish, no refund
    // was scheduled for a rejected request.
    const blocked = await drive(mw, r, 429);
    expect(blocked.nextCalled).toBe(false);
    blocked.res.emit('finish'); // no listener → no-op
    expect(decrementSpy).not.toHaveBeenCalled();
    // Still blocked — the counter was not refunded down.
    expect((await drive(mw, r, 200)).nextCalled).toBe(false);
  });

  it('refunds at most once even if both finish and close fire', async () => {
    const store = makeStore();
    const decrementSpy = vi.spyOn(store, 'decrement');
    const mw = createRateLimiter({ windowMs: 5000, max: 5, skipSuccessful: true, store, now: () => 10_000 });
    const res = (await drive(mw, makeReq(), 200, 'finish')).res;
    res.emit('close'); // second terminal event — must NOT double-refund
    expect(decrementSpy).toHaveBeenCalledTimes(1);
  });

  it('does NOT refund on close when the socket aborts before finish', async () => {
    // On a client abort, `close` fires while res.statusCode is still the default
    // 200 (the route never set its real status — e.g. a failed login it hadn't
    // yet marked 401). Refunding there would credit a request that never
    // completed, so the refund is scheduled ONLY on `finish`.
    const store = makeStore();
    const decrementSpy = vi.spyOn(store, 'decrement');
    const mw = createRateLimiter({ windowMs: 5000, max: 5, skipSuccessful: true, store, now: () => 10_000 });
    await drive(mw, makeReq(), 200, 'close');
    expect(decrementSpy).not.toHaveBeenCalled();
  });

  it('tiered limiters on one response each refund their own counted hit', async () => {
    // Two limiters both count the same request; with a per-LIMITER refund guard
    // both refund on finish. A per-response guard would let only the first tier
    // refund (and the second would appear permanently counted).
    const storeA = makeStore();
    const storeB = makeStore();
    const decA = vi.spyOn(storeA, 'decrement');
    const decB = vi.spyOn(storeB, 'decrement');
    const mwA = createRateLimiter({ windowMs: 5000, max: 5, skipSuccessful: true, store: storeA, now: () => 10_000 });
    const mwB = createRateLimiter({ windowMs: 5000, max: 5, skipSuccessful: true, store: storeB, now: () => 10_000 });
    const req = makeReq();
    const res = makeEventRes(() => {});
    await new Promise<void>((resolve) => {
      void mwA(req, res, () => resolve());
    });
    await new Promise<void>((resolve) => {
      void mwB(req, res, () => resolve());
    });
    res.statusCode = 200;
    res.emit('finish');
    expect(decA).toHaveBeenCalledTimes(1);
    expect(decB).toHaveBeenCalledTimes(1);
  });

  it('default (skipSuccessful unset) does NOT refund — no regression', async () => {
    const store = makeStore();
    const decrementSpy = vi.spyOn(store, 'decrement');
    const mw = createRateLimiter({ windowMs: 5000, max: 1, store, now: () => 10_000 });
    const r = makeReq();
    expect((await drive(mw, r, 200)).nextCalled).toBe(true);
    expect((await drive(mw, r, 200)).nextCalled).toBe(false); // 2nd blocked (counted)
    expect(decrementSpy).not.toHaveBeenCalled();
  });
});

describe('ipResolution (ROG-1094 wiring)', () => {
  /** Drive the limiter to a 429 and capture the bucket key it used. */
  async function keyUsedFor(config: Omit<RateLimiterConfig, 'windowMs' | 'max'>, req: Request): Promise<string> {
    let seenKey = '';
    const mw = createRateLimiter({
      windowMs: 1000,
      max: 0, // reject on the very first hit so we always observe the key
      store: makeStore(),
      now: () => 10_000,
      buildResponseBody: (info) => {
        seenKey = info.key;
        return {};
      },
      ...config,
    });
    await new Promise<void>((resolve) => {
      const made = makeRes(resolve);
      void mw(req, made.res, () => resolve());
    });
    return seenKey;
  }

  it('regression guard: with no ipResolution set, the key is byte-for-byte identical to pre-1.4.0 (plain req.ip)', async () => {
    const req = makeReq({ ip: '203.0.113.9' });
    expect(await keyUsedFor({}, req)).toBe('ip:203.0.113.9');
  });

  it('ignores ipResolution entirely when an explicit keyGenerator is given', async () => {
    const req = makeReq({
      ip: '203.0.113.9',
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    const key = await keyUsedFor(
      { keyGenerator: ipKey, ipResolution: { trustCloudflare: true } },
      req,
    );
    expect(key).toBe('ip:203.0.113.9'); // NOT the CF header — keyGenerator wins
  });

  it('ADVERSARIAL: trustXff keys on the last hop, not a spoofed leading hop', async () => {
    const req = makeReq({
      headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.7' }, // "1.2.3.4" is forged
    });
    const key = await keyUsedFor({ ipResolution: { trustXff: true } }, req);
    expect(key).toBe('ip:203.0.113.7');
  });

  it('trustCloudflare keys on Cf-Connecting-Ip even in the presence of a spoofed XFF', async () => {
    const req = makeReq({
      headers: {
        'cf-connecting-ip': '203.0.113.7',
        'x-forwarded-for': '1.2.3.4, 203.0.113.7',
      },
    });
    const key = await keyUsedFor(
      { ipResolution: { trustCloudflare: true, trustXff: true } },
      req,
    );
    expect(key).toBe('ip:203.0.113.7');
  });

  it('a verified principal still takes precedence over IP resolution', async () => {
    const req = makeReq({
      headers: { 'cf-connecting-ip': '203.0.113.7' },
      securityContext: { principalType: 'user', principalId: 'u1' },
    });
    const key = await keyUsedFor({ ipResolution: { trustCloudflare: true } }, req);
    expect(key).toBe('user:u1');
  });
});
