import type { AuditBufferConfig, AuditEvent } from './types';
/**
 * Buffered, batched audit event queue.
 *
 * The kit owns all the machinery — buffering, size/time-triggered flushing,
 * single-in-flight flush coalescing, re-queue on transient sink failure, and a
 * hard queue cap with drop-oldest — while the service injects the {@link
 * AuditSink} (durability) and decides what to record.
 *
 * GUARANTEES:
 *  - {@link record} is non-blocking and NEVER throws (a broken sink/logger can
 *    never break the request path).
 *  - Audit can never OOM: the queue is hard-capped at `maxQueueSize`; excess
 *    drops the OLDEST events and counts them via `onDropped`.
 *  - At most one `sink.write` is in flight at a time; a size-triggered flush
 *    that arrives mid-flush coalesces instead of double-sending.
 */
export declare class AuditBuffer {
    private readonly sink;
    private readonly maxBufferSize;
    private readonly flushIntervalMs;
    private readonly maxQueueSize;
    private readonly maxCloseRetries;
    private readonly onDropped?;
    private readonly onFlushError?;
    private readonly logger;
    /** FIFO queue of pending events (index 0 = oldest). */
    private queue;
    /** The single in-flight flush, or undefined when idle. */
    private flushing;
    /** Set when a flush is requested while one is already running. */
    private flushRequested;
    private timer;
    private closed;
    constructor(config: AuditBufferConfig);
    /** Log a warning without ever letting a throwing logger break the caller. */
    private safeWarn;
    private startTimer;
    /**
     * Enqueue an event. Non-blocking, never throws. Triggers an async flush once
     * the buffer reaches `maxBufferSize`. Drops oldest events past `maxQueueSize`.
     */
    record(event: AuditEvent): void;
    /** Enforce the hard cap by dropping the oldest events (counted). */
    private enforceQueueCap;
    /**
     * Drain buffered events to the sink. Coalesces with any in-flight flush so at
     * most one `sink.write` runs at a time. Never throws.
     */
    flush(): Promise<void>;
    /**
     * Repeatedly drain the queue while there is work and a follow-up was
     * requested, so events enqueued during a write are not stranded. Stops
     * re-looping when a write FAILS — otherwise a persistently failing sink whose
     * re-queued events keep the buffer at/above `maxBufferSize` would hot-loop
     * forever. Failed events wait for the next timer/size-triggered flush.
     */
    private runFlushLoop;
    /**
     * Drain the current batch exactly once. Returns true on a successful write
     * (or an empty queue), false when the sink rejected. Never throws.
     */
    private flushOnce;
    /** Number of currently queued (not-yet-flushed) events. */
    get size(): number;
    /** Stop the periodic timer. Does NOT flush; use close() to drain. */
    stop(): void;
    /** Alias of stop() for symmetry with the other stores. */
    dispose(): void;
    private clearTimer;
    /**
     * Graceful shutdown: stop the timer and drain remaining events (awaitable).
     * After close(), further record() calls are dropped.
     *
     * A single flush that hits a transient sink failure re-queues its batch and
     * stops looping, so close() retries the flush up to `closeMaxRetries` times
     * (default 3) with a short delay between attempts. If the sink is still
     * failing after that, the events remain queued (inspect via `size`) and were
     * surfaced through `onFlushError` — close() resolves rather than hang forever.
     * Never rejects.
     */
    close(): Promise<void>;
}
