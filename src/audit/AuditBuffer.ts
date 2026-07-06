import type {
  AuditBufferConfig,
  AuditEvent,
  AuditLogger,
  AuditSink,
} from './types';

const DEFAULT_MAX_BUFFER_SIZE = 100;
const DEFAULT_FLUSH_INTERVAL_MS = 5000;
const DEFAULT_MAX_QUEUE_SIZE = 10000;
const DEFAULT_CLOSE_MAX_RETRIES = 3;
const CLOSE_RETRY_DELAY_MS = 25;

function requirePositive(value: number, name: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`AuditBuffer: ${name} must be a positive number`);
  }
  return value;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    (t as { unref?: () => void }).unref?.();
  });
}

const consoleLogger: AuditLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

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
export class AuditBuffer {
  private readonly sink: AuditSink;
  private readonly maxBufferSize: number;
  private readonly flushIntervalMs: number;
  private readonly maxQueueSize: number;
  private readonly maxCloseRetries: number;
  private readonly onDropped?: (count: number) => void;
  private readonly onFlushError?: (err: unknown, events: AuditEvent[]) => void;
  private readonly logger: AuditLogger;

  /** FIFO queue of pending events (index 0 = oldest). */
  private queue: AuditEvent[] = [];
  /** The single in-flight flush, or undefined when idle. */
  private flushing: Promise<void> | undefined;
  /** Set when a flush is requested while one is already running. */
  private flushRequested = false;
  private timer: ReturnType<typeof setInterval> | undefined;
  private closed = false;

  constructor(config: AuditBufferConfig) {
    this.sink = config.sink;
    this.maxBufferSize = requirePositive(
      config.maxBufferSize ?? DEFAULT_MAX_BUFFER_SIZE,
      'maxBufferSize',
    );
    this.flushIntervalMs = config.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
    this.maxQueueSize = requirePositive(
      config.maxQueueSize ?? DEFAULT_MAX_QUEUE_SIZE,
      'maxQueueSize',
    );
    this.maxCloseRetries = config.closeMaxRetries ?? DEFAULT_CLOSE_MAX_RETRIES;
    this.onDropped = config.onDropped;
    this.onFlushError = config.onFlushError;
    this.logger = config.logger ?? consoleLogger;
    this.startTimer();
  }

  /** Log a warning without ever letting a throwing logger break the caller. */
  private safeWarn(message: string, meta?: unknown): void {
    try {
      this.logger.warn(message, meta);
    } catch {
      // A broken logger must never break audit's never-throw guarantee.
    }
  }

  private startTimer(): void {
    if (this.timer || this.flushIntervalMs <= 0) return;
    this.timer = setInterval(() => {
      // Fire-and-forget; flush never rejects.
      void this.flush();
    }, this.flushIntervalMs);
    this.timer.unref?.();
  }

  /**
   * Enqueue an event. Non-blocking, never throws. Triggers an async flush once
   * the buffer reaches `maxBufferSize`. Drops oldest events past `maxQueueSize`.
   */
  record(event: AuditEvent): void {
    try {
      if (this.closed) {
        // After close(), silently drop — the owner is shutting down.
        return;
      }
      this.queue.push(event);
      this.enforceQueueCap();
      if (this.queue.length >= this.maxBufferSize) {
        // Defer to a microtask so sink.write NEVER runs synchronously inside
        // record() (a synchronous sink would otherwise block the request
        // handler until its whole write completes). record() returns first.
        queueMicrotask(() => void this.flush());
      }
    } catch (err) {
      // record() must NEVER throw into the request path.
      this.safeWarn('[express-security-kit] audit record failed', err);
    }
  }

  /** Enforce the hard cap by dropping the oldest events (counted). */
  private enforceQueueCap(): void {
    if (this.queue.length <= this.maxQueueSize) return;
    const dropCount = this.queue.length - this.maxQueueSize;
    this.queue.splice(0, dropCount);
    // Report the drop FIRST and independently so a throwing warn can't skip it.
    try {
      this.onDropped?.(dropCount);
    } catch {
      // onDropped must not break us
    }
    this.safeWarn(
      `[express-security-kit] audit queue overflow; dropped ${dropCount} oldest event(s)`,
    );
  }

  /**
   * Drain buffered events to the sink. Coalesces with any in-flight flush so at
   * most one `sink.write` runs at a time. Never throws.
   */
  flush(): Promise<void> {
    if (this.flushing) {
      // A flush is already running — request a follow-up pass and share its
      // promise so callers awaiting flush() see the whole thing settle.
      this.flushRequested = true;
      return this.flushing;
    }
    this.flushing = this.runFlushLoop().finally(() => {
      this.flushing = undefined;
    });
    return this.flushing;
  }

  /**
   * Repeatedly drain the queue while there is work and a follow-up was
   * requested, so events enqueued during a write are not stranded. Stops
   * re-looping when a write FAILS — otherwise a persistently failing sink whose
   * re-queued events keep the buffer at/above `maxBufferSize` would hot-loop
   * forever. Failed events wait for the next timer/size-triggered flush.
   */
  private async runFlushLoop(): Promise<void> {
    let succeeded = true;
    do {
      this.flushRequested = false;
      succeeded = await this.flushOnce();
      // Loop again only on a SUCCESSFUL write, and only if a follow-up was
      // requested (coalesced flush) or the buffer refilled past the threshold
      // with genuinely new events while we were awaiting the sink.
    } while (
      succeeded &&
      (this.flushRequested || this.queue.length >= this.maxBufferSize)
    );
  }

  /**
   * Drain the current batch exactly once. Returns true on a successful write
   * (or an empty queue), false when the sink rejected. Never throws.
   */
  private async flushOnce(): Promise<boolean> {
    if (this.queue.length === 0) return true;

    // Take the whole current queue as the batch, in insertion order. Keep our
    // own `batch` reference for re-queue, and hand the SINK a COPY so a sink
    // that mutates its argument (then throws) cannot corrupt the re-queue.
    const batch = this.queue;
    this.queue = [];

    try {
      await this.sink.write(batch.slice());
      return true;
    } catch (err) {
      // Transient sink failure: re-queue the failed events at the FRONT (they
      // are older than anything enqueued during the write) so a later flush
      // retries them, then re-apply the hard cap so a persistently failing sink
      // can't grow the queue unbounded.
      this.queue = batch.concat(this.queue);
      this.enforceQueueCap();
      try {
        this.onFlushError?.(err, batch);
      } catch {
        // onFlushError must not break the flush loop
      }
      this.safeWarn(
        '[express-security-kit] audit sink write failed; events re-queued',
        err,
      );
      return false;
    }
  }

  /** Number of currently queued (not-yet-flushed) events. */
  get size(): number {
    return this.queue.length;
  }

  /** Stop the periodic timer. Does NOT flush; use close() to drain. */
  stop(): void {
    this.clearTimer();
  }

  /** Alias of stop() for symmetry with the other stores. */
  dispose(): void {
    this.clearTimer();
  }

  private clearTimer(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

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
  async close(): Promise<void> {
    this.clearTimer();
    this.closed = true;

    for (let attempt = 0; attempt <= this.maxCloseRetries; attempt++) {
      await this.flush();
      if (this.queue.length === 0) return;
      if (attempt < this.maxCloseRetries) {
        await delay(CLOSE_RETRY_DELAY_MS);
      }
    }
    // Still undrained after the bounded retries — leave queued (already
    // surfaced via onFlushError) rather than spin forever.
  }
}
