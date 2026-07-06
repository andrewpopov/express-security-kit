import { describe, it, expect, vi } from 'vitest';
import { AuditBuffer } from '../AuditBuffer';
import type { AuditEvent, AuditSink } from '../types';

function ev(action: string): AuditEvent {
  return { timestamp: '2026-01-01T00:00:00.000Z', action, outcome: 'deny' };
}

/** A sink that records every batch it receives and resolves immediately. */
function recordingSink(): { sink: AuditSink; batches: AuditEvent[][] } {
  const batches: AuditEvent[][] = [];
  return {
    batches,
    sink: {
      write: async (events) => {
        batches.push(events);
      },
    },
  };
}

/** A sink whose writes block until manually released (for coalescing tests). */
function gatedSink() {
  const batches: AuditEvent[][] = [];
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  return {
    batches,
    release,
    sink: {
      write: async (events: AuditEvent[]) => {
        batches.push(events);
        await gate;
      },
    } as AuditSink,
  };
}

const noTimer = { flushIntervalMs: 0 };

describe('AuditBuffer.record non-blocking', () => {
  it('does NOT run a synchronous sink inside the record() call', async () => {
    let wrote = false;
    const sink: AuditSink = {
      write: async (events) => {
        wrote = true; // a synchronous sink would set this during record()
        void events;
      },
    };
    const buf = new AuditBuffer({ sink, maxBufferSize: 1, ...noTimer });
    buf.record(ev('a'));
    // record() returned before any sink work began.
    expect(wrote).toBe(false);
    // ...and the deferred flush runs on a later microtask.
    await Promise.resolve();
    await buf.flush();
    expect(wrote).toBe(true);
    buf.stop();
  });
});

describe('AuditBuffer constructor validation', () => {
  it('throws on non-positive maxBufferSize', () => {
    const { sink } = recordingSink();
    expect(() => new AuditBuffer({ sink, maxBufferSize: 0 })).toThrow();
    expect(() => new AuditBuffer({ sink, maxBufferSize: -1 })).toThrow();
  });
  it('throws on non-positive maxQueueSize', () => {
    const { sink } = recordingSink();
    expect(() => new AuditBuffer({ sink, maxQueueSize: 0 })).toThrow();
    expect(() => new AuditBuffer({ sink, maxQueueSize: -5 })).toThrow();
  });
});

describe('AuditBuffer.record', () => {
  it('enqueues without flushing until maxBufferSize', async () => {
    const { sink, batches } = recordingSink();
    const buf = new AuditBuffer({ sink, maxBufferSize: 3, ...noTimer });
    buf.record(ev('a'));
    buf.record(ev('b'));
    expect(buf.size).toBe(2);
    expect(batches).toHaveLength(0);
    buf.record(ev('c')); // hits threshold → auto flush
    await buf.flush();
    expect(batches.flat().map((e) => e.action)).toEqual(['a', 'b', 'c']);
    buf.stop();
  });

  it('never throws even if the sink throws synchronously on write', async () => {
    const sink: AuditSink = {
      write: () => {
        throw new Error('sink boom');
      },
    };
    const onFlushError = vi.fn();
    const buf = new AuditBuffer({ sink, maxBufferSize: 1, onFlushError, logger: { warn: vi.fn() }, ...noTimer });
    expect(() => buf.record(ev('a'))).not.toThrow();
    await buf.flush();
    expect(onFlushError).toHaveBeenCalled();
    buf.stop();
  });

  it('never throws even if the logger throws, and still calls onDropped', () => {
    const badLogger = {
      warn: () => {
        throw new Error('logger boom');
      },
    };
    const onDropped = vi.fn();
    // Force the overflow path (which logs) with a broken logger.
    const { sink } = recordingSink();
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, maxQueueSize: 1, onDropped, logger: badLogger, ...noTimer });
    expect(() => {
      buf.record(ev('a'));
      buf.record(ev('b')); // overflow → onDropped first, then logger.warn throws (swallowed)
    }).not.toThrow();
    expect(onDropped).toHaveBeenCalledWith(1);
    buf.stop();
  });

  it('flush() and close() still resolve when the logger throws on a sink error', async () => {
    const badLogger = {
      warn: () => {
        throw new Error('logger boom');
      },
    };
    const sink: AuditSink = { write: () => Promise.reject(new Error('sink down')) };
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, logger: badLogger, ...noTimer });
    buf.record(ev('a'));
    // flush must resolve (not reject) even though the internal warn throws.
    await expect(buf.flush()).resolves.toBeUndefined();
    await expect(buf.close()).resolves.toBeUndefined();
  });
});

describe('AuditBuffer.flush ordering & drain', () => {
  it('drains events to the sink in insertion order', async () => {
    const { sink, batches } = recordingSink();
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, ...noTimer });
    for (const a of ['a', 'b', 'c', 'd']) buf.record(ev(a));
    await buf.flush();
    expect(batches.flat().map((e) => e.action)).toEqual(['a', 'b', 'c', 'd']);
    expect(buf.size).toBe(0);
    buf.stop();
  });

  it('is a no-op when empty', async () => {
    const { sink, batches } = recordingSink();
    const buf = new AuditBuffer({ sink, ...noTimer });
    await buf.flush();
    expect(batches).toHaveLength(0);
    buf.stop();
  });
});

describe('AuditBuffer periodic flush', () => {
  it('flushes on the timer interval', async () => {
    vi.useFakeTimers();
    try {
      const { sink, batches } = recordingSink();
      const buf = new AuditBuffer({ sink, maxBufferSize: 100, flushIntervalMs: 1000 });
      buf.record(ev('a'));
      expect(batches).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(1000);
      expect(batches.flat().map((e) => e.action)).toEqual(['a']);
      buf.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('AuditBuffer sink-error re-queue', () => {
  it('re-queues failed events (not lost) and retries on next flush', async () => {
    let failNext = true;
    const batches: AuditEvent[][] = [];
    const sink: AuditSink = {
      write: async (events) => {
        if (failNext) {
          failNext = false;
          throw new Error('transient');
        }
        batches.push(events);
      },
    };
    const onFlushError = vi.fn();
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, onFlushError, logger: { warn: vi.fn() }, ...noTimer });
    buf.record(ev('a'));
    buf.record(ev('b'));
    await buf.flush(); // fails → re-queued
    expect(onFlushError).toHaveBeenCalledTimes(1);
    expect(buf.size).toBe(2); // events retained, not lost
    await buf.flush(); // succeeds
    expect(batches.flat().map((e) => e.action)).toEqual(['a', 'b']);
    expect(buf.size).toBe(0);
    buf.stop();
  });

  it('re-queued events go to the FRONT (older than newly enqueued)', async () => {
    let failNext = true;
    const batches: AuditEvent[][] = [];
    const sink: AuditSink = {
      write: async (events) => {
        if (failNext) {
          failNext = false;
          throw new Error('transient');
        }
        batches.push(events);
      },
    };
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, logger: { warn: vi.fn() }, ...noTimer });
    buf.record(ev('a'));
    await buf.flush(); // 'a' fails, re-queued at front
    buf.record(ev('b')); // enqueued after 'a'
    await buf.flush();
    expect(batches.flat().map((e) => e.action)).toEqual(['a', 'b']);
    buf.stop();
  });
});

describe('AuditBuffer maxQueueSize overflow', () => {
  it('drops oldest and reports the count via onDropped', async () => {
    const { sink, batches } = recordingSink();
    const onDropped = vi.fn();
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, maxQueueSize: 2, onDropped, logger: { warn: vi.fn() }, ...noTimer });
    buf.record(ev('a'));
    buf.record(ev('b'));
    buf.record(ev('c')); // over cap → drop 'a'
    expect(buf.size).toBe(2);
    expect(onDropped).toHaveBeenCalledWith(1);
    await buf.flush();
    expect(batches.flat().map((e) => e.action)).toEqual(['b', 'c']);
    buf.stop();
  });
});

describe('AuditBuffer flush coalescing', () => {
  it('does not double-send a batch when a flush arrives mid-write', async () => {
    const gate = gatedSink();
    // Large buffer so record() never auto-flushes; we drive flush() explicitly.
    const buf = new AuditBuffer({ sink: gate.sink, maxBufferSize: 1000, ...noTimer });
    buf.record(ev('a'));
    buf.record(ev('b'));
    const first = buf.flush(); // starts write of [a, b], blocks on the gate
    // While the write is blocked, enqueue more and request another flush.
    buf.record(ev('c'));
    const second = buf.flush(); // should coalesce, NOT start a parallel write
    // Only one batch has been handed to the sink so far.
    expect(gate.batches).toHaveLength(1);
    expect(gate.batches[0].map((e) => e.action)).toEqual(['a', 'b']);
    gate.release(); // let the first write complete
    await Promise.all([first, second]);
    // The follow-up pass sends 'c' exactly once.
    expect(gate.batches).toHaveLength(2);
    expect(gate.batches[1].map((e) => e.action)).toEqual(['c']);
    // No event was sent twice.
    expect(gate.batches.flat().map((e) => e.action)).toEqual(['a', 'b', 'c']);
    buf.stop();
  });
});

describe('AuditBuffer.close', () => {
  it('flushes remaining events and stops accepting new ones', async () => {
    const { sink, batches } = recordingSink();
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, flushIntervalMs: 1000 });
    buf.record(ev('a'));
    buf.record(ev('b'));
    await buf.close();
    expect(batches.flat().map((e) => e.action)).toEqual(['a', 'b']);
    // record() after close is dropped silently.
    buf.record(ev('c'));
    expect(buf.size).toBe(0);
  });

  it('retries during close: a sink that fails twice then succeeds loses nothing', async () => {
    let attempts = 0;
    const batches: AuditEvent[][] = [];
    const sink: AuditSink = {
      write: async (events) => {
        attempts += 1;
        if (attempts <= 2) throw new Error('transient');
        batches.push(events);
      },
    };
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, closeMaxRetries: 3, logger: { warn: vi.fn() }, ...noTimer });
    buf.record(ev('a'));
    buf.record(ev('b'));
    await buf.close();
    expect(batches.flat().map((e) => e.action)).toEqual(['a', 'b']);
    expect(buf.size).toBe(0);
  });

  it('a sink that always fails: close() resolves after bounded retries, events retained', async () => {
    const onFlushError = vi.fn();
    const sink: AuditSink = { write: () => Promise.reject(new Error('down')) };
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, closeMaxRetries: 2, onFlushError, logger: { warn: vi.fn() }, ...noTimer });
    buf.record(ev('a'));
    await expect(buf.close()).resolves.toBeUndefined();
    // Events not silently lost — still queued and surfaced.
    expect(buf.size).toBe(1);
    // 1 initial + 2 retries = 3 attempts.
    expect(onFlushError).toHaveBeenCalledTimes(3);
  });
});

describe('AuditBuffer sink batch isolation', () => {
  it('a sink that mutates then throws does not corrupt the re-queue', async () => {
    let failNext = true;
    const seen: AuditEvent[][] = [];
    const sink: AuditSink = {
      write: async (events) => {
        if (failNext) {
          failNext = false;
          events.length = 0; // hostile: mutate the passed array
          throw new Error('transient');
        }
        seen.push(events);
      },
    };
    const buf = new AuditBuffer({ sink, maxBufferSize: 100, logger: { warn: vi.fn() }, ...noTimer });
    buf.record(ev('a'));
    buf.record(ev('b'));
    await buf.flush(); // fails after clearing its copy; internal re-queue intact
    expect(buf.size).toBe(2);
    await buf.flush(); // succeeds
    expect(seen.flat().map((e) => e.action)).toEqual(['a', 'b']);
    buf.stop();
  });
});
