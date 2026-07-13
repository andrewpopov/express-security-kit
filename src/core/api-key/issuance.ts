import { randomBytes } from 'node:crypto';
import type { KeyHasher } from './types';
import { sha256Hasher } from './hashers';

/**
 * API-key ISSUANCE (mint/parse/mask/rotate) — the counterpart to
 * {@link ../verifyApiKey.verifyApiKey}, which only verifies. This module owns
 * NO ORM and NO persistence: it is pure functions plus an optional
 * {@link ApiKeyStore} port that a consumer implements against its own schema.
 *
 * Key shape: `<prefix><keyId>.<secret>` — a superset of savoro's
 * `ssk_<keyId>.<secret>` format. `keyId` is a PUBLIC, unhashed lookup id:
 * store it indexed so `ApiKeyStore.findByKeyId` is a plain index lookup,
 * never a table scan or a hash-recompute-and-compare loop over every stored
 * key. `secret` is the only part that must be hashed and kept unguessable;
 * `hash` in {@link ApiKeyMaterial} is the hash of the secret ALONE, produced
 * via the kit's existing hasher seam ({@link sha256Hasher} /
 * `scopedHmacHasher`) — this module adds no second hashing scheme.
 */

/**
 * Material produced by {@link generateApiKey}. `raw` is shown to the caller
 * EXACTLY ONCE — the kit never stores it and callers must not persist it.
 */
export interface ApiKeyMaterial {
  /** Full raw key: `${prefix}${keyId}.${secret}`. Show once; never store. */
  raw: string;
  /** Hash of the SECRET portion only (via the configured hasher). Store this. */
  hash: string;
  /** Public lookup id (unhashed). Store this; index on it. */
  keyId: string;
  /** The prefix this key was generated with. */
  prefix: string;
  /** Last 4 characters of the raw secret, for display masking. */
  last4: string;
}

export interface GenerateApiKeyOptions {
  /** Required prefix, e.g. 'cairn_', 'ssk_', 'smh_'. */
  prefix: string;
  /**
   * Hasher applied to the secret portion. Default: `sha256Hasher()`. Pass
   * `scopedHmacHasher(secret, scope)` to reuse the kit's HMAC seam instead —
   * do not invent a second hashing scheme.
   */
  hasher?: KeyHasher;
  /** Random bytes for the public keyId (hex-encoded, so 2x this many chars). Default 8 (16 hex chars). */
  keyIdBytes?: number;
  /** Random bytes for the secret (base64url-encoded). Default 32. */
  secretBytes?: number;
}

/** Mint a new API key. Pure/synchronous — no I/O, no persistence. */
export function generateApiKey(options: GenerateApiKeyOptions): ApiKeyMaterial {
  const prefix = options.prefix;
  if (!prefix) {
    throw new Error('generateApiKey requires a non-empty prefix');
  }
  const hasher = options.hasher ?? sha256Hasher();
  const keyId = randomBytes(options.keyIdBytes ?? 8).toString('hex');
  const secret = randomBytes(options.secretBytes ?? 32).toString('base64url');
  const raw = `${prefix}${keyId}.${secret}`;
  const hash = hasher(secret);
  const last4 = secret.slice(-4);
  return { raw, hash, keyId, prefix, last4 };
}

export interface ParsedApiKey {
  keyId: string;
  secret: string;
}

/**
 * Parse a raw presented key of the `<prefix><keyId>.<secret>` shape produced
 * by {@link generateApiKey}. Returns `null` (NEVER throws) on any malformed
 * input — callers should treat `null` as a failed auth attempt, not a crash.
 */
export function parseApiKey(raw: string, prefix: string): ParsedApiKey | null {
  if (typeof raw !== 'string' || typeof prefix !== 'string' || prefix.length === 0) {
    return null;
  }
  if (!raw.startsWith(prefix)) return null;
  const rest = raw.slice(prefix.length);
  const dotIndex = rest.indexOf('.');
  if (dotIndex <= 0) return null; // no '.', or nothing before it (empty keyId)
  const keyId = rest.slice(0, dotIndex);
  const secret = rest.slice(dotIndex + 1);
  if (!keyId || !secret) return null;
  return { keyId, secret };
}

/**
 * Build a display mask. Superset of smarthome's `prefix...last4` mask and
 * savoro's `<prefix><keyId>.********` mask: shows the full public
 * `prefix`+`keyId` (never secret, and never a table scan to find it — the
 * caller already has it from a lookup) followed by the secret's `last4`, so
 * logs/support can both identify the key by its lookup id AND visually
 * confirm the tail a user reports. Never reveals the secret.
 */
export function maskApiKey(
  material: Pick<ApiKeyMaterial, 'prefix' | 'keyId' | 'last4'>,
): string {
  // Reject anything that isn't real material. Passing the RAW key here is the
  // obvious mistake, and without this guard it produced
  // "undefinedundefined...undefined" — garbage that still LOOKS like a mask, so
  // a consumer would happily store or display it and never notice.
  if (
    material === null ||
    typeof material !== 'object' ||
    typeof material.prefix !== 'string' ||
    typeof material.keyId !== 'string' ||
    typeof material.last4 !== 'string'
  ) {
    throw new TypeError(
      'maskApiKey expects ApiKeyMaterial ({ prefix, keyId, last4 }), not a raw key string',
    );
  }
  return `${material.prefix}${material.keyId}...${material.last4}`;
}

// ---------------------------------------------------------------------------
// Store port — the kit owns no ORM.
// ---------------------------------------------------------------------------

/** The minimal persisted shape the kit needs. Extend with app fields freely. */
export interface ApiKeyStoreRecord {
  keyId: string;
  /** Hash of the secret (see {@link ApiKeyMaterial.hash}). */
  hash: string;
  expiresAt?: Date | null;
  revoked?: boolean;
  meta?: Record<string, unknown>;
}

export type ApiKeyInsertInput = ApiKeyStoreRecord;

/**
 * Store port. Implement this against your own schema (Prisma, raw SQL, ...);
 * the kit imports no ORM. `transaction` is OPTIONAL: when provided,
 * {@link rotateApiKey} uses it so the new key's insert and the old key's
 * revoke happen atomically (bewks's transactional rotate). When omitted,
 * `rotateApiKey` falls back to insert-then-revoke — a brief window where
 * BOTH keys work, but never a window where NEITHER does (fail SAFE for
 * availability during rotation, at the cost of true atomicity).
 */
export interface ApiKeyStore {
  findByKeyId(keyId: string): Promise<ApiKeyStoreRecord | null>;
  insert(record: ApiKeyInsertInput): Promise<void>;
  revoke(keyId: string): Promise<void>;
  touchLastUsed(keyId: string, at: Date): Promise<void>;
  transaction?<T>(
    fn: (tx: Pick<ApiKeyStore, 'insert' | 'revoke'>) => Promise<T>,
  ): Promise<T>;
}

/**
 * Rotate a key: mint fresh material, insert the new record, and revoke
 * `oldKeyId`. Uses `store.transaction` when available for a genuinely atomic
 * swap (old key invalid, new key valid, no window where either both or
 * neither work); without it, inserts the new key before revoking the old one
 * so there is never a window where neither works.
 */
export async function rotateApiKey(
  store: ApiKeyStore,
  oldKeyId: string,
  options: GenerateApiKeyOptions,
): Promise<ApiKeyMaterial> {
  const material = generateApiKey(options);
  const insertRecord: ApiKeyInsertInput = { keyId: material.keyId, hash: material.hash };

  if (store.transaction) {
    await store.transaction(async (tx) => {
      await tx.insert(insertRecord);
      await tx.revoke(oldKeyId);
    });
  } else {
    await store.insert(insertRecord);
    await store.revoke(oldKeyId);
  }

  return material;
}

// ---------------------------------------------------------------------------
// Throttled lastUsedAt.
// ---------------------------------------------------------------------------

export interface ThrottledTouchLastUsedOptions {
  /** Minimum interval between writes for the same keyId. Default 60_000ms. */
  minIntervalMs?: number;
  /**
   * Called when the underlying `store.touchLastUsed` rejects. Default: none —
   * unlike bewks's `.catch(() => {})`, a caller that wants visibility into
   * write failures MUST be given the chance to get it; pass a logger here
   * rather than silently dropping the error.
   */
  onError?: (keyId: string, err: unknown) => void;
  /** Clock override for tests. Default `Date.now`. */
  now?: () => number;
}

/**
 * Wrap `store.touchLastUsed` so a hot verification path does not write on
 * EVERY request — all four consumer apps currently do exactly that. At most
 * one write per `keyId` per `minIntervalMs` window; calls within the window
 * are dropped (not queued/batched — `lastUsedAt` has a freshness
 * requirement, not a correctness one, so a dropped intermediate update is
 * fine as long as the most recent activity eventually lands).
 *
 * The returned function never throws and never blocks its caller: the write
 * is fired without being awaited, and a rejection is routed to `onError`
 * (never silently swallowed without a seam to observe it).
 */
export function createThrottledTouchLastUsed(
  store: Pick<ApiKeyStore, 'touchLastUsed'>,
  options: ThrottledTouchLastUsedOptions = {},
): (keyId: string) => void {
  const minIntervalMs = options.minIntervalMs ?? 60_000;
  const now = options.now ?? Date.now;
  const last = new Map<string, number>();

  return (keyId: string): void => {
    const t = now();
    const prev = last.get(keyId);
    if (prev !== undefined && t - prev < minIntervalMs) return;
    last.set(keyId, t);
    void store.touchLastUsed(keyId, new Date(t)).catch((err: unknown) => {
      options.onError?.(keyId, err);
    });
  };
}
