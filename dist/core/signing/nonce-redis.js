"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisNonceStore = void 0;
const node_crypto_1 = require("node:crypto");
function hashHex(value) {
    return (0, node_crypto_1.createHash)('sha256').update(value).digest('hex');
}
/**
 * Durable, multi-instance replay-protection store backed by Redis (or an
 * ioredis-compatible client). Implements {@link NonceStore} via the atomic
 * `SET key val PX ttlMs NX` primitive: the SET only succeeds (`'OK'`) when
 * the key does not already exist, so a single round trip both records the
 * nonce and answers "was this a replay?" without a check-then-set race.
 *
 * STRICT reply handling: `'OK'` -> `'ok'`, `null` -> `'replay'`, ANY OTHER
 * reply (an unexpected string, a number, `undefined`, ...) THROWS rather than
 * being guessed at. An ambiguous reply or a lost connection therefore always
 * THROWS — it is never reinterpreted as `'replay'`. This store never
 * internally retries the NX write, which would risk exactly that
 * reinterpretation. A thrown/rejected `client.set` call propagates as-is
 * (store unavailable), so callers fail CLOSED per the {@link NonceStore}
 * contract.
 *
 * The key is `esk:nonce:<sha256hex(scope)>:<sha256hex(nonce)>` — BOTH `scope`
 * and `nonce` are hashed (not just concatenated) so a caller-controlled scope
 * value can never be crafted to collide with a different (scope, nonce) pair
 * via a delimiter-injection ambiguity.
 *
 * This is the ONLY file that depends on a Redis client, and it is the
 * `@andrewpopov/express-security-kit/nonce-redis` subpath export. The main
 * entry (`index.ts`) and the `./core` barrel never import it, keeping the
 * core dependency-free of ioredis.
 */
class RedisNonceStore {
    constructor(client) {
        this.client = client;
    }
    key(scope, nonce) {
        return `esk:nonce:${hashHex(scope)}:${hashHex(nonce)}`;
    }
    async consume(scope, nonce, ttlMs) {
        if (!Number.isFinite(ttlMs) || !Number.isInteger(ttlMs) || ttlMs <= 0) {
            throw new Error(`RedisNonceStore: ttlMs must be a finite positive integer (got ${ttlMs})`);
        }
        const reply = await this.client.set(this.key(scope, nonce), '1', 'PX', ttlMs, 'NX');
        if (reply === 'OK')
            return 'ok';
        if (reply === null)
            return 'replay';
        throw new Error(`RedisNonceStore: unexpected SET reply (store unavailable/ambiguous): ${JSON.stringify(reply)}`);
    }
}
exports.RedisNonceStore = RedisNonceStore;
