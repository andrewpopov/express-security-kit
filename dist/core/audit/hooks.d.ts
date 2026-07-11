import type { SecurityRequest } from '../http';
import type { AuditBuffer } from './AuditBuffer';
import type { AuditEvent } from './types';
export interface AuditHookOptions {
    /** Injectable clock forwarded to buildAuditEvent. */
    now?: () => number;
    /** Id generator forwarded to buildAuditEvent (default crypto.randomUUID). */
    id?: () => string;
}
/**
 * Adapter for `createApiKeyAuth.onFailure` / signing verifier `onFailure`.
 * Records a `deny` (default) event carrying the failure reason. The returned
 * function matches `(req, reason) => void` and never throws.
 */
export declare function auditFailureHook<Req extends SecurityRequest = SecurityRequest>(buffer: AuditBuffer, action: string, outcome?: AuditEvent['outcome'], options?: AuditHookOptions): (req: Req, reason: string) => void;
/**
 * Adapter for `createRateLimiter.onLimit`. Records a `deny` event tagging the
 * limiter key in meta. Matches `(req, key) => void`.
 */
export declare function auditRateLimitHook<Req extends SecurityRequest = SecurityRequest>(buffer: AuditBuffer, action: string, options?: AuditHookOptions): (req: Req, key: string) => void;
/**
 * Adapter for `requireScope.onDenied`. Records a `deny` event. Matches
 * `(req) => void`.
 */
export declare function auditDeniedHook<Req extends SecurityRequest = SecurityRequest>(buffer: AuditBuffer, action: string, options?: AuditHookOptions): (req: Req) => void;
