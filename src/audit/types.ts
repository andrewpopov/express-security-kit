/**
 * A normalized audit event. Produced by {@link buildAuditEvent} (or built by
 * hand) and persisted in batches by an {@link AuditSink}.
 */
export interface AuditEvent {
  /** ISO-8601 timestamp of when the event occurred. */
  timestamp: string;
  /** Service-defined action name, e.g. 'apiKey.auth', 'list.delete'. */
  action: string;
  /** Coarse result of the audited operation. */
  outcome: 'allow' | 'deny' | 'error';
  principalType?: string;
  principalId?: string;
  keyId?: string;
  ip?: string;
  method?: string;
  path?: string;
  /** Machine-readable reason (e.g. an auth failure reason). */
  reason?: string;
  /** Correlation id linking this event to a request/trace. */
  correlationId?: string;
  /** Free-form service-supplied metadata. */
  meta?: Record<string, unknown>;
}

/**
 * Persistence for audit events, INJECTED by the consuming service (Prisma,
 * file, HTTP, …). The kit owns buffering/batching; the sink owns durability.
 * `write` receives a batch in insertion order and should resolve once the batch
 * is durably stored (or reject to trigger re-queue/retry).
 */
export interface AuditSink {
  write(events: AuditEvent[]): Promise<void>;
}

/** Minimal logger surface; defaults to console. */
export interface AuditLogger {
  warn: (message: string, meta?: unknown) => void;
}

export interface AuditBufferConfig {
  /** Injected persistence. */
  sink: AuditSink;
  /** Flush automatically once this many events are buffered. Default 100. */
  maxBufferSize?: number;
  /** Periodic flush interval in ms. Default 5000. */
  flushIntervalMs?: number;
  /**
   * Max extra flush attempts during `close()` when the sink is failing, with a
   * short delay between attempts. Default 3. Beyond this, undrained events are
   * left queued (surfaced via onFlushError) rather than hanging shutdown.
   */
  closeMaxRetries?: number;
  /**
   * Hard cap on queued events. Beyond this, the OLDEST events are dropped
   * (counted) so audit can never OOM or block the request path. Default 10000.
   */
  maxQueueSize?: number;
  /** Called with the number of events dropped due to the hard cap. */
  onDropped?: (count: number) => void;
  /** Called when sink.write rejects; the failed events are re-queued for retry. */
  onFlushError?: (err: unknown, events: AuditEvent[]) => void;
  /** Logger for internal warnings. Default console. */
  logger?: AuditLogger;
  /** Injectable clock (ms). Default Date.now. */
  now?: () => number;
}
