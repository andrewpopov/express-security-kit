import type { SecurityContext } from '../context';
import type { SecurityRequest } from '../http';
import {
  ApiKeyAuthConfigCore,
  ApiKeyFailureReason,
  ApiKeyRecord,
  ApiKeyStaticKey,
} from './types';
import { sha256Hasher, timingSafeEqualHex } from './hashers';
import { normalizeIp } from './normalizeIp';

/**
 * Result of {@link verifyApiKey}. A discriminated union — the verifier reports
 * the decision WITHOUT touching `res` or `req.securityContext`, so a caller with
 * a unified/multi-method auth flow (try api-key, else JWT) can decide whether to
 * fall through or reject.
 */
export type ApiKeyVerifyOutcome =
  | { ok: true; context: SecurityContext; record: ApiKeyRecord | null }
  | {
      ok: false;
      reason: ApiKeyFailureReason;
      /**
       * Whether a credential was actually presented. `false` ONLY when the
       * credential is genuinely ABSENT (no/empty header) — the case where a
       * caller may fall through to another auth method. `true` for a malformed
       * or otherwise-invalid presented key (a real failed attempt).
       */
      present: boolean;
      /**
       * 403 for `ip_denied`; `config.errorStatus` (default 503) for `error`
       * (an infrastructure failure, not an auth failure); 401 for everything
       * else.
       */
      status: number;
    };

/**
 * Outcome of extracting the presented credential:
 * - `absent`    — the header is not present or empty.
 * - `malformed` — the header IS present but cannot be parsed into a key (e.g.
 *   `Authorization: Basic x`, a bare `Bearer`). A FAILED auth attempt.
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
export function extractRawKey<Req extends SecurityRequest = SecurityRequest>(
  req: Req,
  headerName: string,
): ExtractResult {
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

export function buildDefaultContext(record: ApiKeyRecord): SecurityContext {
  const context: SecurityContext = {
    principalType: 'apiKey',
    principalId: record.id,
    keyId: record.id,
    scopes: record.scopes,
    rateLimitOverride: record.rateLimitOverride ?? undefined,
  };
  if (record.meta !== undefined) context.meta = record.meta;
  return context;
}

const failMissing = (
  reason: ApiKeyFailureReason,
  present: boolean,
  status: number = 401,
): ApiKeyVerifyOutcome => ({ ok: false, reason, present, status });

/** `config.errorStatus`, defaulting to 503. Never throws — a pathological
 * throwing getter falls back to the default rather than escaping the
 * fail-closed catch block that calls this. */
function resolveErrorStatus<Req extends SecurityRequest>(
  config: ApiKeyAuthConfigCore<Req>,
): number {
  try {
    return typeof config.errorStatus === 'number' ? config.errorStatus : 503;
  } catch {
    return 503;
  }
}

/**
 * Verify an API key against the request, returning a discriminated outcome
 * WITHOUT sending HTTP or mutating the request. This is the shared verification
 * core (extract → prefix → static-key → hash+lookup → hash re-compare → expiry
 * → IP allowlist → build context) used by {@link createApiKeyAuth} and by
 * services that own their own response handling (e.g. a unified api-key-or-JWT
 * flow).
 *
 * NEVER throws: an unexpected error (e.g. a throwing `lookup` or `hasher`)
 * resolves to `{ ok: false, reason: 'error', present: true, status: 503 }`
 * (status configurable via `config.errorStatus`/`onError`) — fail closed,
 * but reported as an infrastructure failure, not a 401 authentication
 * failure.
 * It ignores the middleware-only config fields (`optional`, `onFailure`,
 * `logger`) and does NOT call `onFailure`; it DOES run `onAuthenticated`.
 */
export async function verifyApiKey<Req extends SecurityRequest = SecurityRequest>(
  config: ApiKeyAuthConfigCore<Req>,
  req: Req,
): Promise<ApiKeyVerifyOutcome> {
  try {
    // Resolve config-derived values inside the try so the never-throws
    // guarantee holds even against a pathological throwing config getter.
    const headerName = config.headerName ?? 'authorization';
    const hasher = config.hasher ?? sha256Hasher();

    // 1. Extract the raw key.
    const extracted = extractRawKey(req, headerName);
    if (extracted.kind !== 'key') {
      // present=false only for a genuinely absent credential.
      return failMissing(
        extracted.kind === 'malformed' ? 'malformed' : 'missing',
        extracted.kind === 'malformed',
      );
    }
    const rawKey = extracted.key;

    // 2. Prefix check (generic failure — do not reveal it was the prefix).
    if (!rawKey.startsWith(config.prefix)) {
      return failMissing('bad_prefix', true);
    }

    // 3. Static bootstrap/service keys (constant-time), checked before DB.
    const staticKey = matchStaticKey(rawKey, config.staticKeys);
    if (staticKey) {
      return {
        ok: true,
        record: null,
        context: {
          principalType: 'service',
          principalId: staticKey.principalId ?? staticKey.name,
          keyId: staticKey.name,
        },
      };
    }

    // 4. Canonical host-owned raw authentication, or the legacy hash lookup.
    // The raw path is specifically for indexed public-id formats where only
    // the secret segment is hashed; never pre-hash the whole wire credential.
    let record: ApiKeyRecord | null;
    if (config.rawAuthenticator) {
      const authenticated = await config.rawAuthenticator(rawKey, req);
      if (!authenticated.ok) return failMissing(authenticated.reason ?? 'not_found', true);
      record = authenticated.record;
    } else {
      const computedHash = hasher(rawKey);
      record = await config.lookup(computedHash);
      if (!record) return failMissing('not_found', true);
      if (!record.hash || !timingSafeEqualHex(record.hash, computedHash)) {
        return failMissing('hash_mismatch', true);
      }
    }

    // 5. Expiry. A present-but-invalid Date (getTime() === NaN) is treated as
    //    expired — never trust a corrupt expiry to grant access.
    if (record.expiresAt) {
      const expiryTime = record.expiresAt.getTime();
      if (Number.isNaN(expiryTime) || expiryTime <= Date.now()) {
        return failMissing('expired', true);
      }
    }

    // 6. IP allowlist (403, not 401). Both sides are normalized (see
    //    normalizeIp) before comparing — otherwise a socket reporting an
    //    IPv4-mapped IPv6 address (`::ffff:203.0.113.7`, common behind some
    //    proxies/load balancers) would spuriously fail to match an allowlist
    //    entry of `203.0.113.7`. Still an EXACT match — no CIDR/range
    //    support. Its correctness depends entirely on a properly configured
    //    Express `trust proxy`; a too-broad trust proxy lets X-Forwarded-For
    //    spoofing defeat it. '*' disables the check; an undefined/malformed
    //    req.ip is denied unless '' is explicitly listed.
    if (
      record.allowedIps &&
      record.allowedIps.length > 0 &&
      !record.allowedIps.includes('*') &&
      !record.allowedIps.map(normalizeIp).includes(normalizeIp(req.ip))
    ) {
      return failMissing('ip_denied', true, 403);
    }

    // 7. Build the SecurityContext.
    const context: SecurityContext = config.onAuthenticated
      ? await config.onAuthenticated(req, record)
      : buildDefaultContext(record);
    return { ok: true, context, record };
  } catch {
    // FAIL CLOSED on any unexpected error (e.g. a throwing lookup or
    // hasher). This is an INFRASTRUCTURE failure, not an authentication
    // failure — never an allow, but reported at `errorStatus` (default 503,
    // not 401) so it doesn't look like every key was revoked.
    return failMissing('error', true, resolveErrorStatus(config));
  }
}
