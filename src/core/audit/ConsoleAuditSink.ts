import type { AuditEvent, AuditSink } from './types';

export interface ConsoleAuditSinkLogger {
  log: (line: string) => void;
}

/**
 * Reference {@link AuditSink} that writes one JSON line per event to the
 * injected logger (default `console.log`). Intended as a DEV default only —
 * production deployments should inject a DURABLE sink (Prisma, append-only
 * file, log-shipping HTTP endpoint, …) that survives process restarts.
 */
export class ConsoleAuditSink implements AuditSink {
  private readonly logger: ConsoleAuditSinkLogger;

  constructor(logger: ConsoleAuditSinkLogger = { log: (line) => console.log(line) }) {
    this.logger = logger;
  }

  async write(events: AuditEvent[]): Promise<void> {
    for (const event of events) {
      // Guard EACH event independently: a single un-stringifiable event (e.g.
      // circular `meta`) or a throwing logger for one line must not fail the
      // whole batch — otherwise AuditBuffer would re-queue and re-emit the
      // events that DID succeed, producing duplicates. Emit a minimal fallback
      // line for the bad event and continue.
      let line: string;
      try {
        line = JSON.stringify(event);
      } catch {
        line = this.fallbackLine(event);
      }
      try {
        this.logger.log(line);
      } catch {
        // A throwing logger for one line must not fail the batch either.
      }
    }
  }

  /** Best-effort minimal JSON when the full event can't be serialized. */
  private fallbackLine(event: AuditEvent): string {
    try {
      return JSON.stringify({
        timestamp: event.timestamp,
        action: event.action,
        outcome: event.outcome,
        _note: 'meta omitted: event not serializable',
      });
    } catch {
      return '{"_note":"audit event not serializable"}';
    }
  }
}
