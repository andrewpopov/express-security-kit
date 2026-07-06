import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Request } from 'express';
import { createRateLimiter, RateLimiterConfig } from '../createRateLimiter';
import { MemoryRateLimitStore, RateLimitStore } from '../store';
import { ipKey } from '../keyGenerator';

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

describe('fail-open', () => {
  it('allows the request when the store throws', async () => {
    const throwingStore: RateLimitStore = {
      hit: () => Promise.reject(new Error('redis down')),
      reset: () => Promise.resolve(),
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
