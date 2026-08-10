import type { SecurityContext } from '../context';
import type { SecurityRequest } from '../http';
import {
  ApiKeyAuthConfigCore,
  ApiKeyAuthLogger,
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
       * or `unavailable` (an infrastructure failure, not an auth failure);
       * 401 for everything else.
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
    hmacSecret: record.hmacSecret ?? undefined,
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
 * `ApiKeyAuthConfigCore` needs at least one of `rawAuthenticator` (canonical)
 * or `lookup` (legacy) — supplying NEITHER can't work under any code path, so
 * it is rejected: {@link createApiKeyAuth} (Express and Fastify) calls this
 * eagerly at construction and throws with this message; {@link verifyApiKey}
 * calls it per-request and — consistent with its documented never-throws
 * contract — folds an invalid config into the existing `reason: 'error'`
 * vocabulary instead of throwing. (Before this check existed, "neither"
 * already produced the same `reason: 'error'`/503 outcome via an uncaught
 * `TypeError` from calling `undefined` as `lookup`, swallowed by
 * `verifyApiKey`'s fail-closed catch-all — this makes that failure explicit
 * and, for `createApiKeyAuth`, immediate at construction instead of on the
 * first request.)
 *
 * Supplying BOTH is deliberately NOT an error here — see {@link
 * warnIfBothCredentialPathsConfigured}. `lookup` used to be REQUIRED, so
 * every canonical-path consumer was forced to supply a dead `lookup` just to
 * satisfy the type; rejecting "both" at construction would break every one of
 * them on upgrade, punishing them for a workaround the old type forced on
 * them. `rawAuthenticator` silently wins today, unchanged — the warning is
 * how the "both" case gets deprecated without breaking anyone on this release.
 *
 * Returns `null` when the config is valid.
 */
export function describeApiKeyConfigError<Req extends SecurityRequest>(
  config: Pick<ApiKeyAuthConfigCore<Req>, 'rawAuthenticator' | 'lookup'>,
): string | null {
  const hasRawAuthenticator = typeof config.rawAuthenticator === 'function';
  const hasLookup = typeof config.lookup === 'function';
  if (!hasRawAuthenticator && !hasLookup) {
    return "supply either 'rawAuthenticator' (canonical) or 'lookup' (legacy)";
  }
  return null;
}

/** Default logger for {@link warnIfBothCredentialPathsConfigured} when
 * `config.logger` is absent — same shape/behavior as the `consoleLogger`
 * default in `createApiKeyAuth` (Express/Fastify). */
const defaultAuthLogger: ApiKeyAuthLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

/**
 * Configs that have already been warned about, so the deprecation notice
 * fires ONCE per config object rather than once per request. A `WeakSet` so
 * a long-lived config never leaks: once it's garbage collected, so is its
 * entry. Module-level and shared by design — {@link createApiKeyAuth}
 * (Express/Fastify) calls this at construction and {@link verifyApiKey} calls
 * it per-request for direct callers that bypass `createApiKeyAuth`; whichever
 * runs first against a given config object warns, the other is then a no-op.
 */
const warnedBothConfigured = new WeakSet<object>();

/**
 * Warn, ONCE per config object, when both `rawAuthenticator` and `lookup`
 * are configured. Behavior is unchanged (`rawAuthenticator` wins, `lookup` is
 * silently ignored) — this is a deprecation notice, not an enforcement:
 * supplying both will become a construction-time error in the next major
 * version, so remove the now-unnecessary `lookup` ahead of that. Matches
 * `AuditBuffer`'s `safeWarn` shape: a broken/throwing logger must NEVER break
 * the caller, so the logger call is wrapped in try/catch.
 */
export function warnIfBothCredentialPathsConfigured<Req extends SecurityRequest>(
  config: Pick<ApiKeyAuthConfigCore<Req>, 'rawAuthenticator' | 'lookup' | 'logger'>,
): void {
  if (typeof config.rawAuthenticator !== 'function' || typeof config.lookup !== 'function') {
    return;
  }
  if (warnedBothConfigured.has(config)) return;
  warnedBothConfigured.add(config);
  try {
    (config.logger ?? defaultAuthLogger).warn(
      "[express-security-kit] ApiKeyAuthConfigCore: both 'rawAuthenticator' and 'lookup' are configured. " +
        "'rawAuthenticator' wins and 'lookup' is ignored (unchanged behavior). This is DEPRECATED: remove " +
        "the now-unnecessary 'lookup' — supplying both will become a construction-time error in the next " +
        'major version.',
    );
  } catch {
    // A broken/throwing logger must never break auth.
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
 * NEVER throws: an unexpected error (e.g. a throwing `lookup` or `hasher`),
 * or a config missing BOTH of `rawAuthenticator`/`lookup` (see {@link
 * describeApiKeyConfigError}), resolves to `{ ok: false, reason: 'error',
 * present: true, status: 503 }` (status configurable via
 * `config.errorStatus`/`onError`) — fail closed, but reported as an
 * infrastructure failure, not a 401 authentication failure. A config
 * supplying BOTH does not error — `rawAuthenticator` wins, `lookup` is
 * ignored, and a one-time deprecation warning is logged (see {@link
 * warnIfBothCredentialPathsConfigured}).
 * It ignores the middleware-only config fields (`optional`, `onFailure`) and
 * does NOT call `onFailure`; it DOES run `onAuthenticated`, and it DOES use
 * `logger` for the "both configured" deprecation warning above.
 */
export async function verifyApiKey<Req extends SecurityRequest = SecurityRequest>(
  config: ApiKeyAuthConfigCore<Req>,
  req: Req,
): Promise<ApiKeyVerifyOutcome> {
  try {
    // 0. Config shape: at least one of rawAuthenticator/lookup must be set.
    // createApiKeyAuth already rejected "neither" eagerly at construction (a
    // thrown Error, so the message actually reaches the developer); reaching
    // here means a caller invoked verifyApiKey directly with a bad config.
    // Fail closed via the existing 'error' vocabulary rather than throwing —
    // this function's contract is NEVER to throw.
    if (describeApiKeyConfigError(config)) {
      return failMissing('error', true, resolveErrorStatus(config));
    }
    // "Both configured" is not an error — deprecated, warned once, and
    // rawAuthenticator wins below (step 4), unchanged from today's behavior.
    warnIfBothCredentialPathsConfigured(config);

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
      if (!authenticated.ok) {
        const reason = authenticated.reason ?? 'not_found';
        // 'unavailable' is an infrastructure failure, not an auth failure —
        // treat it exactly like the internal 'error' path (mirrors the catch
        // block below): fail closed, but at errorStatus (default 503), not 401.
        return reason === 'unavailable'
          ? failMissing('unavailable', true, resolveErrorStatus(config))
          : failMissing(reason, true);
      }
      record = authenticated.record;
    } else {
      // describeApiKeyConfigError already guaranteed lookup is set whenever
      // rawAuthenticator isn't — narrow it explicitly for TS, since it can't
      // infer that runtime invariant from a separately-called function.
      const lookup = config.lookup;
      if (!lookup) return failMissing('error', true, resolveErrorStatus(config));
      const computedHash = hasher(rawKey);
      record = await lookup(computedHash);
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
