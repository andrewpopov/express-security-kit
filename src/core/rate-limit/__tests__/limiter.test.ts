import { describe, it, expect, vi, afterEach } from 'vitest';
import { createRateLimitCore } from '../limiter';
import { MemoryRateLimitStore, RateLimitStore, HitResult } from '../store';
import type { SecurityRequest } from '../../http';

// Proof the decision engine is framework-free: every fixture here is a plain
// object shaped like `SecurityRequest`, never an Express (or Fastify) request.
function req(partial: Partial<SecurityRequest> = {}): SecurityRequest {
  return { headers: {}, ip: '1.2.3.4', ...partial };
}

const stores: MemoryRateLimitStore[] = [];
function makeStore(...args: ConstructorParameters<typeof MemoryRateLimitStore>) {
  const s = new MemoryRateLimitStore(...args);
  stores.push(s);
  return s;
}
afterEach(() => {
  while (stores.length) stores.pop()!.stop();
});

/** A store whose `hit()` always resolves with a caller-chosen fixed result. */
function makeFixedHitStore(result: HitResult): RateLimitStore {
  return {
    hit: () => Promise.resolve(result),
    reset: () => Promise.resolve(),
    decrement: () => undefined,
  };
}

describe('fixed window', () => {
  it('allows exactly max, rejects max + 1', async () => {
    const store = makeStore();
    const core = createRateLimitCore({ windowMs: 1000, max: 2, store, now: () => 10_000 });
    const r = req();
    expect((await core.evaluate(r)).type).toBe('allow'); // 1
    expect((await core.evaluate(r)).type).toBe('allow'); // 2 (== max)
    expect((await core.evaluate(r)).type).toBe('reject'); // max + 1
  });
});

describe('sliding window', () => {
  it('weights the previous window by remaining time (concrete arithmetic)', async () => {
    const windowMs = 1000;
    // resetAt=2000 means the current window started at 1000. now=1500 is
    // exactly halfway through -> elapsedInCurrent=500 -> weightPrevious=0.5.
    const store = makeFixedHitStore({ current: 1, previous: 10, resetAt: 2000 });
    const core = createRateLimitCore({
      windowMs,
      max: 100,
      algorithm: 'sliding',
      store,
      now: () => 1500,
    });
    const outcome = await core.evaluate(req());
    expect(outcome.type).toBe('allow');
    if (outcome.type !== 'allow') throw new Error('expected allow');
    // weighted = previous(10) * weight(0.5) + current(1) = 5 + 1 = 6
    expect(outcome.decision.used).toBe(6);
  });
});

describe('headers', () => {
  it('yields an empty headers array in both outcomes when headers:false', async () => {
    const allowStore = makeStore();
    const allowCore = createRateLimitCore({
      windowMs: 1000,
      max: 5,
      store: allowStore,
      headers: false,
      now: () => 10_000,
    });
    const allowOutcome = await allowCore.evaluate(req());
    expect(allowOutcome.type).toBe('allow');
    if (allowOutcome.type === 'allow') expect(allowOutcome.headers).toEqual([]);

    const rejectStore = makeStore();
    const rejectCore = createRateLimitCore({
      windowMs: 1000,
      max: 0,
      store: rejectStore,
      headers: false,
      now: () => 10_000,
    });
    const rejectOutcome = await rejectCore.evaluate(req());
    expect(rejectOutcome.type).toBe('reject');
    if (rejectOutcome.type === 'reject') expect(rejectOutcome.headers).toEqual([]);
  });

  it('includes Retry-After only on the reject outcome, never on allow', async () => {
    const allowStore = makeStore();
    const allowCore = createRateLimitCore({ windowMs: 1000, max: 5, store: allowStore, now: () => 10_000 });
    const allowOutcome = await allowCore.evaluate(req());
    expect(allowOutcome.type).toBe('allow');
    if (allowOutcome.type === 'allow') {
      expect(allowOutcome.headers.some(([name]) => name === 'Retry-After')).toBe(false);
    }

    const rejectStore = makeStore();
    const rejectCore = createRateLimitCore({ windowMs: 1000, max: 0, store: rejectStore, now: () => 10_000 });
    const rejectOutcome = await rejectCore.evaluate(req());
    expect(rejectOutcome.type).toBe('reject');
    if (rejectOutcome.type === 'reject') {
      expect(rejectOutcome.headers.some(([name]) => name === 'Retry-After')).toBe(true);
    }
  });
});

describe('fail-open', () => {
  it('a throwing store.hit yields skip/store-error', async () => {
    const throwingStore: RateLimitStore = {
      hit: () => Promise.reject(new Error('redis down')),
      reset: () => Promise.resolve(),
      decrement: () => undefined,
    };
    const core = createRateLimitCore({ windowMs: 1000, max: 1, store: throwingStore, now: () => 10_000 });
    const outcome = await core.evaluate(req());
    expect(outcome).toEqual({ type: 'skip', reason: 'store-error' });
  });

  it('a throwing keyGenerator yields skip/unexpected-error', async () => {
    const store = makeStore();
    const core = createRateLimitCore({
      windowMs: 1000,
      max: 1,
      store,
      keyGenerator: () => {
        throw new Error('boom');
      },
      now: () => 10_000,
    });
    const outcome = await core.evaluate(req());
    expect(outcome).toEqual({ type: 'skip', reason: 'unexpected-error' });
  });
});

describe('onSettled', () => {
  it('is absent without skipSuccessful', async () => {
    const store = makeStore();
    const core = createRateLimitCore({ windowMs: 1000, max: 5, store, now: () => 10_000 });
    const outcome = await core.evaluate(req());
    expect(outcome.type).toBe('allow');
    if (outcome.type === 'allow') expect(outcome.onSettled).toBeUndefined();
  });

  it('is present with skipSuccessful, and decrements only for a status < 400', async () => {
    const store = makeStore();
    const decrementSpy = vi.spyOn(store, 'decrement');
    const core = createRateLimitCore({
      windowMs: 1000,
      max: 5,
      skipSuccessful: true,
      store,
      now: () => 10_000,
    });
    const outcome = await core.evaluate(req());
    expect(outcome.type).toBe('allow');
    if (outcome.type !== 'allow' || !outcome.onSettled) {
      throw new Error('expected an allow outcome with onSettled');
    }

    outcome.onSettled(500); // failed request -> no refund
    expect(decrementSpy).not.toHaveBeenCalled();

    outcome.onSettled(200); // success -> refund
    expect(decrementSpy).toHaveBeenCalledTimes(1);
    expect(decrementSpy).toHaveBeenCalledWith('ip:1.2.3.4', 1000, 10_000);
  });
});
