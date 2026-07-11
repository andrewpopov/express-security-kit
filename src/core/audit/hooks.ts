import type { SecurityRequest } from '../http';
import type { AuditBuffer } from './AuditBuffer';
import type { AuditEvent } from './types';
import { buildAuditEvent } from './buildAuditEvent';

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
export function auditFailureHook<Req extends SecurityRequest = SecurityRequest>(
  buffer: AuditBuffer,
  action: string,
  outcome: AuditEvent['outcome'] = 'deny',
  options: AuditHookOptions = {},
): (req: Req, reason: string) => void {
  return (req, reason) => {
    try {
      // String(reason) can throw if reason has a hostile toString — guard it.
      let reasonStr: string;
      try {
        reasonStr = String(reason);
      } catch {
        reasonStr = 'unknown';
      }
      buffer.record(
        buildAuditEvent(req, { action, outcome, reason: reasonStr }, options),
      );
    } catch {
      // Hooks are called from other middlewares' hot paths — never throw.
    }
  };
}

/**
 * Adapter for `createRateLimiter.onLimit`. Records a `deny` event tagging the
 * limiter key in meta. Matches `(req, key) => void`.
 */
export function auditRateLimitHook<Req extends SecurityRequest = SecurityRequest>(
  buffer: AuditBuffer,
  action: string,
  options: AuditHookOptions = {},
): (req: Req, key: string) => void {
  return (req, key) => {
    try {
      buffer.record(
        buildAuditEvent(
          req,
          { action, outcome: 'deny', reason: 'rate_limited', meta: { key } },
          options,
        ),
      );
    } catch {
      // never throw from a middleware hook
    }
  };
}

/**
 * Adapter for `requireScope.onDenied`. Records a `deny` event. Matches
 * `(req) => void`.
 */
export function auditDeniedHook<Req extends SecurityRequest = SecurityRequest>(
  buffer: AuditBuffer,
  action: string,
  options: AuditHookOptions = {},
): (req: Req) => void {
  return (req) => {
    try {
      buffer.record(
        buildAuditEvent(
          req,
          { action, outcome: 'deny', reason: 'scope_denied' },
          options,
        ),
      );
    } catch {
      // never throw from a middleware hook
    }
  };
}
