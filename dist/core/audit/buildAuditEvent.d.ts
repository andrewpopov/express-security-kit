import type { SecurityRequest } from '../http';
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
    /**
     * Generator for the event's optional `id` field. Default
     * `crypto.randomUUID`. Inject a deterministic generator (e.g. `() =>
     * 'fixed-id'`) for tests that assert exact event shapes. See
     * {@link AuditEvent.id} for the dedupe contract this enables.
     */
    id?: () => string;
}
/**
 * Normalize a request + outcome into an {@link AuditEvent}, pulling
 * principalType/principalId/keyId from `req.securityContext` and ip/method/path
 * from the request. Pure and defensive: it NEVER throws, so it is safe to call
 * from any hook on any request shape (including partially-built test doubles).
 */
export declare function buildAuditEvent<Req extends SecurityRequest = SecurityRequest>(req: Req, input: BuildAuditEventInput, options?: BuildAuditEventOptions): AuditEvent;
