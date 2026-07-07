import type { Request } from 'express';
import type { SecurityContext } from '../types';

/**
 * A stored API-key record, as returned by the service's `lookup`. The kit never
 * stores keys itself — the service owns persistence. `hash` is the hashed form
 * of the raw key (using the same `hasher` the verifier is configured with).
 */
export interface ApiKeyRecord {
  /** Stable identifier for this key (becomes principalId/keyId by default). */
  id: string;
  /** Hashed raw key (hex), produced by the configured KeyHasher. */
  hash: string;
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

export interface ApiKeyStaticKey {
  /** Human name / identifier for this bootstrap key (becomes keyId). */
  name: string;
  /** The raw secret value, compared constant-time against the presented key. */
  value: string;
  /** Optional principalId; defaults to `name`. */
  principalId?: string;
}

export interface ApiKeyAuthConfig {
  /** Required key prefix (e.g. 'cairn_', 'ssk_ak_'). Keys must start with it. */
  prefix: string;
  /** Hasher for DB-backed keys. Default: sha256Hasher(). */
  hasher?: KeyHasher;
  /** Look up a stored record by hashed key. Return null when not found. */
  lookup: (hash: string) => Promise<ApiKeyRecord | null>;
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
    req: Request,
    key: ApiKeyRecord,
  ) => SecurityContext | Promise<SecurityContext>;
  /**
   * Audit hook invoked on EVERY auth failure with the specific machine-readable
   * reason. The HTTP response stays generic; the reason is for your logs only.
   * May be async — a returned promise's rejection is caught and logged (never
   * awaited). MUST NOT send a response; the middleware owns the 401/403.
   */
  onFailure?: (
    req: Request,
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
  | 'error';
