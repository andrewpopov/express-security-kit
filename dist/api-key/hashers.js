"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256Hasher = sha256Hasher;
exports.scopedHmacHasher = scopedHmacHasher;
exports.timingSafeEqualHex = timingSafeEqualHex;
const node_crypto_1 = require("node:crypto");
/**
 * Plain SHA-256 hex hasher: `sha256(rawKey)`. The common default for DB-backed
 * keys (stoki `ssk_ak_`, cairn `cairn_`).
 */
function sha256Hasher() {
    return (rawKey) => (0, node_crypto_1.createHash)('sha256').update(rawKey).digest('hex');
}
/**
 * Scoped HMAC hasher: `HMAC-SHA256(key = `${secret}:${scope}`, msg = rawKey)`.
 * This reproduces smarthome's stored-key format EXACTLY (verified by unit test)
 * so smarthome can adopt the kit without rehashing its existing keys.
 */
function scopedHmacHasher(secret, scope) {
    const hmacKey = `${secret}:${scope}`;
    return (rawKey) => (0, node_crypto_1.createHmac)('sha256', hmacKey).update(rawKey).digest('hex');
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
function timingSafeEqualHex(a, b) {
    try {
        const bufA = Buffer.from(a, 'utf8');
        const bufB = Buffer.from(b, 'utf8');
        if (bufA.length !== bufB.length) {
            // Burn comparable time; comparing bufA to itself never throws and avoids
            // branching on content before returning the (already-known) false.
            (0, node_crypto_1.timingSafeEqual)(bufA, bufA);
            return false;
        }
        return (0, node_crypto_1.timingSafeEqual)(bufA, bufB);
    }
    catch {
        return false;
    }
}
