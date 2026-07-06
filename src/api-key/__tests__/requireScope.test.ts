import { describe, it, expect, vi } from 'vitest';
import type { Request } from 'express';
import { requireScope } from '../requireScope';
import type { SecurityContext } from '../../types';

interface Outcome {
  status?: number;
  body?: any;
  nextCalled: boolean;
}

function makeReq(ctx?: SecurityContext): Request {
  return { headers: {}, securityContext: ctx } as Request;
}

function invoke(mw: ReturnType<typeof requireScope>, req: Request): Outcome {
  const outcome: Outcome = { nextCalled: false };
  const res: any = {
    status(code: number) {
      outcome.status = code;
      return res;
    },
    json(payload: unknown) {
      outcome.body = payload;
      return res;
    },
  };
  mw(req, res, () => {
    outcome.nextCalled = true;
  });
  return outcome;
}

describe('requireScope', () => {
  it('calls next when the predicate returns true', () => {
    const ctx: SecurityContext = { principalType: 'apiKey', scopes: ['admin'] };
    const out = invoke(
      requireScope((c) => Array.isArray(c?.scopes) && c!.scopes.includes('admin')),
      makeReq(ctx),
    );
    expect(out.nextCalled).toBe(true);
  });

  it('responds 403 (generic) when the predicate returns false', () => {
    const out = invoke(requireScope(() => false), makeReq({ principalType: 'apiKey' }));
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(403);
    expect(out.body).toEqual({ error: { code: 'FORBIDDEN', message: 'Forbidden' } });
  });

  it('denies (403) when securityContext is missing', () => {
    const out = invoke(requireScope((c) => c !== undefined), makeReq(undefined));
    expect(out.status).toBe(403);
    expect(out.nextCalled).toBe(false);
  });

  it('denies (403) and calls onDenied when the predicate throws', () => {
    const onDenied = vi.fn();
    const out = invoke(
      requireScope(() => {
        throw new Error('policy boom');
      }, { onDenied }),
      makeReq({ principalType: 'apiKey' }),
    );
    expect(out.status).toBe(403);
    expect(onDenied).toHaveBeenCalled();
  });

  it('denies (403) when an async predicate returns a Promise (even of true)', () => {
    const warn = vi.fn();
    // Misuse: predicate is async. The Promise is truthy but its value is
    // unknown synchronously — must NOT let the request through.
    const asyncPredicate = (() => Promise.resolve(false)) as unknown as Parameters<
      typeof requireScope
    >[0];
    const out = invoke(
      requireScope(asyncPredicate, { logger: { warn } }),
      makeReq({ principalType: 'apiKey' }),
    );
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(403);
    expect(warn).toHaveBeenCalled();
  });

  it('denies (403) when a Promise-of-true is returned (bypass guard)', () => {
    const asyncPredicate = (() => Promise.resolve(true)) as unknown as Parameters<
      typeof requireScope
    >[0];
    const out = invoke(requireScope(asyncPredicate), makeReq({ principalType: 'apiKey' }));
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(403);
  });

  it('denies (403) when the predicate returns a truthy non-boolean', () => {
    const objPredicate = (() => ({ ok: true })) as unknown as Parameters<
      typeof requireScope
    >[0];
    const out = invoke(requireScope(objPredicate), makeReq({ principalType: 'apiKey' }));
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(403);
  });

  it('only a literal true proceeds (1 is not enough)', () => {
    const onePredicate = (() => 1) as unknown as Parameters<typeof requireScope>[0];
    const out = invoke(requireScope(onePredicate), makeReq({ principalType: 'apiKey' }));
    expect(out.nextCalled).toBe(false);
    expect(out.status).toBe(403);
  });

  it('catches an async onDenied rejection without unhandled rejection', () => {
    const warn = vi.fn();
    const out = invoke(
      requireScope(() => false, {
        onDenied: () => Promise.reject(new Error('audit boom')),
        logger: { warn },
      }),
      makeReq({ principalType: 'apiKey' }),
    );
    expect(out.status).toBe(403);
  });
});
