import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import { buildAuditEvent } from '../buildAuditEvent';

function req(partial: Partial<Request> = {}): Request {
  return { headers: {}, ...partial } as Request;
}

describe('buildAuditEvent', () => {
  it('pulls principal fields from securityContext and req fields', () => {
    const event = buildAuditEvent(
      req({
        ip: '10.0.0.9',
        method: 'DELETE',
        originalUrl: '/api/lists/1',
        securityContext: { principalType: 'apiKey', principalId: 'p1', keyId: 'k1' },
      }),
      { action: 'list.delete', outcome: 'allow', correlationId: 'corr-1', meta: { n: 2 } },
      { now: () => 1700000000000 },
    );
    expect(event).toEqual({
      timestamp: '2023-11-14T22:13:20.000Z',
      action: 'list.delete',
      outcome: 'allow',
      principalType: 'apiKey',
      principalId: 'p1',
      keyId: 'k1',
      ip: '10.0.0.9',
      method: 'DELETE',
      path: '/api/lists/1',
      correlationId: 'corr-1',
      meta: { n: 2 },
    });
  });

  it('leaves fields undefined when securityContext is missing', () => {
    const event = buildAuditEvent(req({ ip: '1.1.1.1' }), {
      action: 'x',
      outcome: 'deny',
    });
    expect(event.principalType).toBeUndefined();
    expect(event.principalId).toBeUndefined();
    expect(event.keyId).toBeUndefined();
    expect(event.reason).toBeUndefined();
    expect(event.ip).toBe('1.1.1.1');
    expect(event.action).toBe('x');
    expect(event.outcome).toBe('deny');
    expect(typeof event.timestamp).toBe('string');
  });

  it('falls back to req.path when originalUrl is absent', () => {
    const event = buildAuditEvent(
      req({ path: '/fallback' } as Partial<Request>),
      { action: 'a', outcome: 'error' },
    );
    expect(event.path).toBe('/fallback');
  });

  it('never throws on a hostile/partial request object', () => {
    const hostile = {
      get ip(): string {
        throw new Error('ip boom');
      },
      get securityContext(): never {
        throw new Error('ctx boom');
      },
    } as unknown as Request;
    let event!: ReturnType<typeof buildAuditEvent>;
    expect(() => {
      event = buildAuditEvent(hostile, { action: 'a', outcome: 'error' });
    }).not.toThrow();
    expect(event.action).toBe('a');
    expect(event.outcome).toBe('error');
  });
});
