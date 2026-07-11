import type { KeyHasher } from './types';
/**
 * Plain SHA-256 hex hasher: `sha256(rawKey)`. The common default for DB-backed
 * keys (stoki `ssk_ak_`, cairn `cairn_`).
 */
export declare function sha256Hasher(): KeyHasher;
/**
 * Scoped HMAC hasher: `HMAC-SHA256(key = `${secret}:${scope}`, msg = rawKey)`.
 * This reproduces smarthome's stored-key format EXACTLY (verified by unit test)
 * so smarthome can adopt the kit without rehashing its existing keys.
 */
export declare function scopedHmacHasher(secret: string, scope: string): KeyHasher;
/**
 * Constant-time comparison for hex (or any ASCII) strings.
 *
 * - Returns false on a length mismatch, but WITHOUT an early-out timing leak:
 *   when lengths differ we still perform a timingSafeEqual against a same-length
 *   buffer so the code path takes comparable time regardless of where/why the
 *   inputs differ. (Input length itself is inherently observable; content is
 *   not.)
 * - Never throws — any unexpected input yields false.
 */
export declare function timingSafeEqualHex(a: string, b: string): boolean;
