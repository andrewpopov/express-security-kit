import type { Request } from 'express';
import type { AuditEvent } from './types';
export interface BuildAuditEventInput {
    action: string;
    outcome: AuditEvent['outcome'];
    reason?: string;
    correlationId?: string;
    meta?: Record<string, unknown>;
}
export interface BuildAuditEventOptions {
    /** Injectable clock (ms). Default Date.now. Converted to an ISO string. */
    now?: () => number;
}
/**
 * Normalize a request + outcome into an {@link AuditEvent}, pulling
 * principalType/principalId/keyId from `req.securityContext` and ip/method/path
 * from the request. Pure and defensive: it NEVER throws, so it is safe to call
 * from any hook on any request shape (including partially-built test doubles).
 */
export declare function buildAuditEvent(req: Request, input: BuildAuditEventInput, options?: BuildAuditEventOptions): AuditEvent;
