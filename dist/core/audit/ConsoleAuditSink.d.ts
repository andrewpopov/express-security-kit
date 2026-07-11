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
export declare class ConsoleAuditSink implements AuditSink {
    private readonly logger;
    constructor(logger?: ConsoleAuditSinkLogger);
    write(events: AuditEvent[]): Promise<void>;
    /** Best-effort minimal JSON when the full event can't be serialized. */
    private fallbackLine;
}
