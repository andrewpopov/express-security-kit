import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { KeyHasher } from './types';

/**
 * Plain SHA-256 hex hasher: `sha256(rawKey)`. The common default for DB-backed
 * keys (stoki `ssk_ak_`, cairn `cairn_`).
 */
export function sha256Hasher(): KeyHasher {
  return (rawKey: string): string =>
    createHash('sha256').update(rawKey).digest('hex');
}

/**
 * Scoped HMAC hasher: `HMAC-SHA256(key = `${secret}:${scope}`, msg = rawKey)`.
 * This reproduces smarthome's stored-key format EXACTLY (verified by unit test)
 * so smarthome can adopt the kit without rehashing its existing keys.
 */
export function scopedHmacHasher(secret: string, scope: string): KeyHasher {
  const hmacKey = `${secret}:${scope}`;
  return (rawKey: string): string =>
    createHmac('sha256', hmacKey).update(rawKey).digest('hex');
}

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
export function timingSafeEqualHex(a: string, b: string): boolean {
  try {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) {
      // Burn comparable time; comparing bufA to itself never throws and avoids
      // branching on content before returning the (already-known) false.
      timingSafeEqual(bufA, bufA);
      return false;
    }
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}
