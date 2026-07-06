import { describe, it, expect } from 'vitest';
import { ConsoleAuditSink } from '../ConsoleAuditSink';
import type { AuditEvent } from '../types';

const ev = (action: string): AuditEvent => ({
  timestamp: '2026-01-01T00:00:00.000Z',
  action,
  outcome: 'allow',
});

describe('ConsoleAuditSink', () => {
  it('writes one JSON line per event to the injected logger', async () => {
    const lines: string[] = [];
    const sink = new ConsoleAuditSink({ log: (l) => lines.push(l) });
    await sink.write([ev('a'), ev('b')]);
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).action).toBe('a');
    expect(JSON.parse(lines[1]).action).toBe('b');
  });

  it('emits the other events (and a fallback) when one has circular meta; never throws', async () => {
    const lines: string[] = [];
    const sink = new ConsoleAuditSink({ log: (l) => lines.push(l) });
    const circular: AuditEvent = { ...ev('bad'), meta: {} };
    (circular.meta as Record<string, unknown>).self = circular.meta; // circular

    await expect(
      sink.write([ev('a'), circular, ev('c')]),
    ).resolves.toBeUndefined();

    // All three lines emitted — the bad one did NOT fail the batch (no requeue).
    expect(lines).toHaveLength(3);
    expect(JSON.parse(lines[0]).action).toBe('a');
    const fallback = JSON.parse(lines[1]);
    expect(fallback.action).toBe('bad');
    expect(fallback._note).toMatch(/not serializable/);
    expect(fallback.meta).toBeUndefined();
    expect(JSON.parse(lines[2]).action).toBe('c');
  });
});
