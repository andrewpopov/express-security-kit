import type { SecurityContext } from '../context';
import type { SecurityRequest } from '../http';

/**
 * A stored API-key record, as returned by the service's `lookup`. The kit never
 * stores keys itself — the service owns persistence. Legacy hash lookup uses
 * `hash`; canonical raw authenticators do not need to expose hash material.
 */
export interface ApiKeyRecord {
  /** Stable identifier for this key (becomes principalId/keyId by default). */
  id: string;
  /** Legacy hashed raw key (hex), produced by the configured KeyHasher. */
  hash?: string;
  /** Optional expiry; a key with `expiresAt <= now` is rejected. */
  expiresAt?: Date | null;
  /**
   * Optional source-IP allowlist. When set and non-empty, the request IP must
   * be listed (or the list must contain '*'). Empty/absent = no IP restriction.
   *
   * Matching is an EXACT string comparison against `req.ip` — no CIDR or range
   * support. It depends entirely on a correct Express `trust proxy` setting: a
   * too-broad trust proxy lets a client spoof `X-Forwarded-For` and defeat the
   * allowlist. '*' disables the check; an undefined `req.ip` is denied unless
   * '' is explicitly listed.
   */
  allowedIps?: string[] | null;
  /** Opaque scope/permission payload; interpreted by the service via requireScope. */
  scopes?: unknown;
  /** Per-key rate-limit override, consumed by the rate limiter's default resolver. */
  rateLimitOverride?: { windowMs: number; max: number } | null;
  /**
   * Optional per-key HMAC secret for Phase 3 request signing. Stored here so a
   * single lookup serves both auth and (later) signature verification; unused
   * by the Phase 2 verifier.
   */
  hmacSecret?: string | null;
  /**
   * Free-form service-specific data (e.g. `{ orgId }`). Copied to the built
   * SecurityContext's `meta` so a service can stash data at lookup time and read
   * it back from `outcome.context.meta` / `outcome.record.meta`.
   */
  meta?: Record<string, unknown>;
}

/** Hashes a raw key into its stored (hex) form. */
export type KeyHasher = (rawKey: string) => string;

/**
 * Host-owned credential verification seam. It receives the raw credential and
 * performs its own indexed-id lookup and constant-time secret verification.
 * The security kit only translates a successful record into SecurityContext.
 */
export type RawApiKeyAuthenticator<Req extends SecurityRequest = SecurityRequest> = (
  rawKey: string,
  req: Req,
) => Promise<RawApiKeyAuthentication>;

export type RawApiKeyAuthentication =
  | { ok: true; record: ApiKeyRecord }
  | {
      ok: false;
      /**
       * `'unavailable'` means the authenticator's own backing infrastructure
       * (key store, pepper ring, config) could not be consulted — e.g. a
       * pepper ring that hasn't finished loading. It is treated exactly like
       * the kit's internal `'error'` path: reported at `config.errorStatus`
       * (default 503, `onError`-overridable), never 401/403, and NEVER an
       * authentication (still fail-closed). Use it instead of throwing so the
       * infra-vs-auth-failure distinction survives — a throw is caught by
       * `verifyApiKey` and already maps to `'error'`, so `'unavailable'` only
       * matters when the authenticator wants to report this INLINE rather
       * than by throwing.
       */
      reason?: Exclude<ApiKeyFailureReason, 'missing' | 'malformed' | 'bad_prefix' | 'ip_denied' | 'error'>;
    };

export interface ApiKeyStaticKey {
  /** Human name / identifier for this bootstrap key (becomes keyId). */
  name: string;
  /** The raw secret value, compared constant-time against the presented key. */
  value: string;
  /** Optional principalId; defaults to `name`. */
  principalId?: string;
}

/**
 * Generic over the request type so a consumer-authored `onAuthenticated` /
 * `onFailure` callback typed against a concrete request (e.g. Express
 * `Request`) still type-checks: `express/index.ts` re-exports a
 * `Req`-pinned alias (`ApiKeyAuthConfig = ApiKeyAuthConfigCore<Request>`)
 * rather than the `SecurityRequest`-default form.
 */
export interface ApiKeyAuthConfigCore<Req extends SecurityRequest = SecurityRequest> {
  /** Required key prefix (e.g. 'cairn_', 'ssk_ak_'). Keys must start with it. */
  prefix: string;
  /** Hasher for DB-backed keys. Default: sha256Hasher(). */
  hasher?: KeyHasher;
  /** Look up a stored record by hashed key. Return null when not found. */
  lookup: (hash: string) => Promise<ApiKeyRecord | null>;
  /**
   * Canonical credential path. When supplied, the kit does not hash or look up
   * the raw key itself; `lookup` remains required only for legacy callers and
   * is ignored. This lets api-access-kit own credential formats and peppers.
   */
  rawAuthenticator?: RawApiKeyAuthenticator<Req>;
  /**
   * Header carrying the key. Default 'authorization' (parsed as `Bearer <key>`).
   * Any other name (e.g. 'x-api-key') uses the raw trimmed header value.
   */
  headerName?: string;
  /**
   * Static bootstrap/service keys checked (constant-time) before DB lookup.
   * Authenticated as a `service` principal.
   */
  staticKeys?: ApiKeyStaticKey[];
  /**
   * Map an authenticated record to a SecurityContext (may be async — e.g. cairn
   * minting a bot-user). When omitted, a default apiKey context is built.
   */
  onAuthenticated?: (
    req: Req,
    key: ApiKeyRecord,
  ) => SecurityContext | Promise<SecurityContext>;
  /**
   * Audit hook invoked on EVERY auth failure with the specific machine-readable
   * reason. The HTTP response stays generic; the reason is for your logs only.
   * May be async — a returned promise's rejection is caught and logged (never
   * awaited). MUST NOT send a response; the middleware owns the 401/403.
   */
  onFailure?: (
    req: Req,
    reason: ApiKeyFailureReason,
  ) => void | Promise<unknown>;
  /**
   * When true, a genuinely ABSENT credential (no/empty header) calls next()
   * unauthenticated instead of 401. A PRESENT-but-malformed credential is still
   * rejected with 401 even in optional mode.
   */
  optional?: boolean;
  /** Logger for audit-hook rejections. Default: console. */
  logger?: ApiKeyAuthLogger;
  /**
   * HTTP status returned when verification reason is `'error'` or
   * `'unavailable'` — the check could NOT be performed (a throwing
   * `lookup`/`hasher`, e.g. a DB outage, or a `rawAuthenticator` reporting its
   * backing infrastructure is unavailable, e.g. an unloaded pepper ring), as
   * distinct from an authentication FAILURE (bad/unknown/expired key, which
   * is always 401/403 regardless of this setting). Defaults to **503**: an
   * infrastructure failure is not the same failure mode as a bad key, and
   * reporting it as 401 makes monitoring blind to outages and causes clients
   * to treat valid keys as revoked and re-provision. This knob only changes
   * the status/body of the failure response — it can NEVER turn an
   * infrastructure failure into an allow (verifyApiKey still fails closed).
   */
  errorStatus?: number;
  /**
   * Optional full override of the response sent when reason is `'error'` or
   * `'unavailable'`. Return `{ status, body }` to customize both;
   * return/resolve nothing to fall back to `errorStatus`. May be async. A
   * throw or rejection here is caught and logged, and the `errorStatus`
   * default is used instead — this hook can never itself cause an allow or
   * leave the request unanswered.
   */
  onError?: (
    req: Req,
  ) => ApiKeyErrorResponse | void | Promise<ApiKeyErrorResponse | void>;
}

/** Response override returned by {@link ApiKeyAuthConfigCore.onError}. */
export interface ApiKeyErrorResponse {
  status: number;
  body?: unknown;
}

/** Minimal logger surface; defaults to console. */
export interface ApiKeyAuthLogger {
  warn: (message: string, meta?: unknown) => void;
}

/** Machine-readable failure reasons passed to onFailure (never to the client). */
export type ApiKeyFailureReason =
  | 'missing'
  | 'malformed'
  | 'bad_prefix'
  | 'not_found'
  | 'hash_mismatch'
  | 'expired'
  | 'ip_denied'
  | 'error'
  | 'unavailable';
