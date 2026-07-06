import { describe, it, expect, vi } from 'vitest';
import type { Request } from 'express';
import { AuditBuffer } from '../AuditBuffer';
import {
  auditFailureHook,
  auditRateLimitHook,
  auditDeniedHook,
} from '../hooks';
import type { AuditEvent, AuditSink } from '../types';

function req(partial: Partial<Request> = {}): Request {
  return {
    headers: {},
    ip: '10.0.0.1',
    method: 'POST',
    originalUrl: '/api/x',
    securityContext: { principalType: 'apiKey', principalId: 'p1', keyId: 'k1' },
    ...partial,
  } as Request;
}

function bufferCapturing(): { buffer: AuditBuffer; events: AuditEvent[]; stop: () => void } {
  const events: AuditEvent[] = [];
  const sink: AuditSink = { write: async (batch) => void events.push(...batch) };
  const buffer = new AuditBuffer({ sink, maxBufferSize: 1, flushIntervalMs: 0 });
  return { buffer, events, stop: () => buffer.stop() };
}

describe('audit hook adapters', () => {
  it('auditFailureHook records a deny event with the reason', async () => {
    const { buffer, events, stop } = bufferCapturing();
    const hook = auditFailureHook(buffer, 'apiKey.auth', 'deny', { now: () => 1700000000000 });
    hook(req(), 'not_found');
    await buffer.flush();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      action: 'apiKey.auth',
      outcome: 'deny',
      reason: 'not_found',
      principalId: 'p1',
      keyId: 'k1',
    });
    stop();
  });

  it('auditFailureHook honors a custom outcome', async () => {
    const { buffer, events, stop } = bufferCapturing();
    auditFailureHook(buffer, 'signing.verify', 'error')(req(), 'store_error');
    await buffer.flush();
    expect(events[0].outcome).toBe('error');
    stop();
  });

  it('auditRateLimitHook records the limiter key in meta', async () => {
    const { buffer, events, stop } = bufferCapturing();
    auditRateLimitHook(buffer, 'ratelimit')(req(), 'user:p1');
    await buffer.flush();
    expect(events[0]).toMatchObject({
      action: 'ratelimit',
      outcome: 'deny',
      reason: 'rate_limited',
      meta: { key: 'user:p1' },
    });
    stop();
  });

  it('auditDeniedHook records a scope_denied event', async () => {
    const { buffer, events, stop } = bufferCapturing();
    auditDeniedHook(buffer, 'scope')(req());
    await buffer.flush();
    expect(events[0]).toMatchObject({
      action: 'scope',
      outcome: 'deny',
      reason: 'scope_denied',
    });
    stop();
  });

  it('auditFailureHook never throws on a hostile reason (throwing toString)', async () => {
    const { buffer, events, stop } = bufferCapturing();
    const hostileReason = {
      toString() {
        throw new Error('toString boom');
      },
    } as unknown as string;
    expect(() => auditFailureHook(buffer, 'a')(req(), hostileReason)).not.toThrow();
    await buffer.flush();
    // The event was still recorded, with a safe fallback reason.
    expect(events).toHaveLength(1);
    expect(events[0].reason).toBe('unknown');
    stop();
  });

  it('hooks never throw when called from middleware (broken buffer sink)', async () => {
    const throwingSink: AuditSink = {
      write: () => {
        throw new Error('sink down');
      },
    };
    const buffer = new AuditBuffer({ sink: throwingSink, maxBufferSize: 1, logger: { warn: vi.fn() }, flushIntervalMs: 0 });
    const failure = auditFailureHook(buffer, 'a');
    const rate = auditRateLimitHook(buffer, 'b');
    const denied = auditDeniedHook(buffer, 'c');
    expect(() => failure(req(), 'r')).not.toThrow();
    expect(() => rate(req(), 'k')).not.toThrow();
    expect(() => denied(req())).not.toThrow();
    await buffer.flush();
    buffer.stop();
  });
});
