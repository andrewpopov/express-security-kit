import type { KeyHasher } from './types';
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
export declare function generateApiKey(options: GenerateApiKeyOptions): ApiKeyMaterial;
export interface ParsedApiKey {
    keyId: string;
    secret: string;
}
/**
 * Parse a raw presented key of the `<prefix><keyId>.<secret>` shape produced
 * by {@link generateApiKey}. Returns `null` (NEVER throws) on any malformed
 * input — callers should treat `null` as a failed auth attempt, not a crash.
 */
export declare function parseApiKey(raw: string, prefix: string): ParsedApiKey | null;
/**
 * Build a display mask. Superset of smarthome's `prefix...last4` mask and
 * savoro's `<prefix><keyId>.********` mask: shows the full public
 * `prefix`+`keyId` (never secret, and never a table scan to find it — the
 * caller already has it from a lookup) followed by the secret's `last4`, so
 * logs/support can both identify the key by its lookup id AND visually
 * confirm the tail a user reports. Never reveals the secret.
 */
export declare function maskApiKey(material: Pick<ApiKeyMaterial, 'prefix' | 'keyId' | 'last4'>): string;
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
    transaction?<T>(fn: (tx: Pick<ApiKeyStore, 'insert' | 'revoke'>) => Promise<T>): Promise<T>;
}
/**
 * Rotate a key: mint fresh material, insert the new record, and revoke
 * `oldKeyId`. Uses `store.transaction` when available for a genuinely atomic
 * swap (old key invalid, new key valid, no window where either both or
 * neither work); without it, inserts the new key before revoking the old one
 * so there is never a window where neither works.
 */
export declare function rotateApiKey(store: ApiKeyStore, oldKeyId: string, options: GenerateApiKeyOptions): Promise<ApiKeyMaterial>;
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
export declare function createThrottledTouchLastUsed(store: Pick<ApiKeyStore, 'touchLastUsed'>, options?: ThrottledTouchLastUsedOptions): (keyId: string) => void;
