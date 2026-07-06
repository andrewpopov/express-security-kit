import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { SecurityContext } from '../types';
import {
  ApiKeyAuthConfig,
  ApiKeyFailureReason,
  ApiKeyRecord,
  ApiKeyStaticKey,
} from './types';
import type { ApiKeyAuthLogger } from './types';
import { sha256Hasher, timingSafeEqualHex } from './hashers';

const consoleLogger: ApiKeyAuthLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

/** Send a generic 401. The specific reason is NEVER leaked to the client. */
function unauthorized(res: Response): void {
  res.status(401).json({
    error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
  });
}

/** Send a generic 403. */
function forbidden(res: Response): void {
  res.status(403).json({
    error: { code: 'FORBIDDEN', message: 'Forbidden' },
  });
}

/**
 * Outcome of extracting the presented credential:
 * - `absent`    — the header is not present or empty. In `optional` mode this
 *   is the only case that passes through as anonymous.
 * - `malformed` — the header IS present but cannot be parsed into a key (e.g.
 *   `Authorization: Basic x`, a bare `Bearer`). This is a FAILED auth attempt,
 *   rejected even in `optional` mode.
 * - `{ key }`   — a usable raw key.
 */
type ExtractResult =
  | { kind: 'absent' }
  | { kind: 'malformed' }
  | { kind: 'key'; key: string };

/**
 * Extract the raw presented key from the request.
 * - 'authorization' header: parsed as `Bearer <key>`.
 * - any other header: the raw trimmed value.
 */
function extractRawKey(req: Request, headerName: string): ExtractResult {
  const raw = req.headers?.[headerName.toLowerCase()];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return { kind: 'absent' };
  const trimmed = value.trim();
  if (trimmed.length === 0) return { kind: 'absent' };

  if (headerName.toLowerCase() === 'authorization') {
    const match = /^Bearer\s+(.+)$/i.exec(trimmed);
    if (!match) return { kind: 'malformed' };
    const token = match[1].trim();
    return token.length > 0
      ? { kind: 'key', key: token }
      : { kind: 'malformed' };
  }
  return { kind: 'key', key: trimmed };
}

function matchStaticKey(
  rawKey: string,
  staticKeys: ApiKeyStaticKey[] | undefined,
): ApiKeyStaticKey | null {
  if (!staticKeys) return null;
  for (const staticKey of staticKeys) {
    // Constant-time full-string compare of raw secrets (these are not hashed).
    if (timingSafeEqualHex(rawKey, staticKey.value)) {
      return staticKey;
    }
  }
  return null;
}

/**
 * Build an API-key authentication middleware.
 *
 * Auth FAILS CLOSED: any failure (missing/bad/expired/denied key, or an
 * unexpected error such as a throwing `lookup`) yields a GENERIC 401/403 and the
 * request does NOT proceed. This is the opposite of the rate limiter, which
 * fails open. Only the `onFailure` audit hook receives the specific reason.
 */
export function createApiKeyAuth(config: ApiKeyAuthConfig): RequestHandler {
  const headerName = config.headerName ?? 'authorization';
  const hasher = config.hasher ?? sha256Hasher();
  const logger = config.logger ?? consoleLogger;

  const fail = (
    req: Request,
    res: Response,
    reason: ApiKeyFailureReason,
    kind: 'unauthorized' | 'forbidden' = 'unauthorized',
  ): void => {
    // An audit hook must never affect the auth decision, throw out, or leak an
    // unhandled rejection. Swallow sync throws and attach a .catch to promises.
    if (config.onFailure) {
      try {
        const maybePromise = config.onFailure(req, reason) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as Promise<unknown>).then === 'function'
        ) {
          (maybePromise as Promise<unknown>).catch((err) =>
            logger.warn('[express-security-kit] onFailure hook rejected', err),
          );
        }
      } catch (err) {
        logger.warn('[express-security-kit] onFailure hook threw', err);
      }
    }
    if (kind === 'forbidden') forbidden(res);
    else unauthorized(res);
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // 1. Extract the raw key.
      const extracted = extractRawKey(req, headerName);
      if (extracted.kind !== 'key') {
        // In optional mode, pass through ONLY a genuinely absent credential; a
        // present-but-unparseable credential is a failed auth attempt and is
        // rejected even when optional.
        if (extracted.kind === 'absent' && config.optional) {
          // Unauthenticated pass-through; no securityContext is set.
          return next();
        }
        return fail(
          req,
          res,
          extracted.kind === 'malformed' ? 'malformed' : 'missing',
        );
      }
      const rawKey = extracted.key;

      // 2. Prefix check (generic failure — do not reveal it was the prefix).
      if (!rawKey.startsWith(config.prefix)) {
        return fail(req, res, 'bad_prefix');
      }

      // 3. Static bootstrap/service keys (constant-time), checked before DB.
      const staticKey = matchStaticKey(rawKey, config.staticKeys);
      if (staticKey) {
        req.securityContext = {
          principalType: 'service',
          principalId: staticKey.principalId ?? staticKey.name,
          keyId: staticKey.name,
        };
        return next();
      }

      // 4. Hash + DB lookup.
      const computedHash = hasher(rawKey);
      const record = await config.lookup(computedHash);
      if (!record) {
        return fail(req, res, 'not_found');
      }

      // 5. Defense in depth: constant-time compare the stored hash against the
      //    computed hash even though lookup was keyed by hash.
      if (!timingSafeEqualHex(record.hash, computedHash)) {
        return fail(req, res, 'hash_mismatch');
      }

      // 6. Expiry. A present-but-invalid Date (getTime() === NaN) is treated as
      //    expired — never trust a corrupt expiry to grant access.
      if (record.expiresAt) {
        const expiryTime = record.expiresAt.getTime();
        if (Number.isNaN(expiryTime) || expiryTime <= Date.now()) {
          return fail(req, res, 'expired');
        }
      }

      // 7. IP allowlist (403, not 401). NOTE: EXACT string match against
      //    req.ip — no CIDR/range support. Its correctness depends entirely on
      //    a properly configured Express `trust proxy`; a too-broad trust proxy
      //    lets X-Forwarded-For spoofing defeat it. '*' disables the check; an
      //    undefined req.ip is denied unless '' is explicitly listed.
      if (
        record.allowedIps &&
        record.allowedIps.length > 0 &&
        !record.allowedIps.includes('*') &&
        !record.allowedIps.includes(req.ip ?? '')
      ) {
        return fail(req, res, 'ip_denied', 'forbidden');
      }

      // 8. Build the SecurityContext and proceed.
      const context: SecurityContext = config.onAuthenticated
        ? await config.onAuthenticated(req, record)
        : buildDefaultContext(record);
      req.securityContext = context;
      return next();
    } catch {
      // FAIL CLOSED on any unexpected error (e.g. lookup throws).
      return fail(req, res, 'error');
    }
  };
}

function buildDefaultContext(record: ApiKeyRecord): SecurityContext {
  return {
    principalType: 'apiKey',
    principalId: record.id,
    keyId: record.id,
    scopes: record.scopes,
    rateLimitOverride: record.rateLimitOverride ?? undefined,
  };
}
