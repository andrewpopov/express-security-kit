import { randomUUID } from 'node:crypto';
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
export function buildAuditEvent<Req extends SecurityRequest = SecurityRequest>(
  req: Req,
  input: BuildAuditEventInput,
  options: BuildAuditEventOptions = {},
): AuditEvent {
  const now = options.now ?? Date.now;

  let timestamp: string;
  try {
    timestamp = new Date(now()).toISOString();
  } catch {
    timestamp = new Date().toISOString();
  }

  const event: AuditEvent = {
    timestamp,
    action: input.action,
    outcome: input.outcome,
  };

  try {
    event.id = (options.id ?? randomUUID)();
  } catch {
    // Id generation must never break event construction — omit it on throw.
  }

  try {
    const ctx = req?.securityContext;
    if (ctx) {
      if (ctx.principalType !== undefined) event.principalType = ctx.principalType;
      if (ctx.principalId !== undefined) event.principalId = ctx.principalId;
      if (ctx.keyId !== undefined) event.keyId = ctx.keyId;
    }
    if (typeof req?.ip === 'string') event.ip = req.ip;
    if (typeof req?.method === 'string') event.method = req.method;
    const path = req?.originalUrl ?? (req as { path?: string })?.path;
    if (typeof path === 'string') event.path = path;
  } catch {
    // Never let request introspection throw — emit what we have.
  }

  if (input.reason !== undefined) event.reason = input.reason;
  if (input.correlationId !== undefined) event.correlationId = input.correlationId;
  if (input.meta !== undefined) event.meta = input.meta;

  return event;
}
