import type { NonceStore } from './nonceStore';
/**
 * Minimal structural subset of the ioredis client this store uses. Declaring
 * it locally means we do NOT import ioredis's types at the type level either,
 * so the core stays free of a hard ioredis dependency. Pass a real ioredis
 * instance (or an ioredis-compatible client) at construction.
 *
 * This mirrors ioredis's actual `SET key value PX milliseconds NX` overload
 * (see `RedisCommander.d.ts`: `set(key, value, "PX", milliseconds, "NX",
 * callback?): Result<"OK" | null, Context>`), which resolves to
 * `Promise<'OK' | null>` when called without a callback.
 */
export interface RedisLikeNonceClient {
    set(key: string, value: string, px: 'PX', ttlMs: number, nx: 'NX'): Promise<'OK' | null>;
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
export declare class RedisNonceStore implements NonceStore {
    private readonly client;
    constructor(client: RedisLikeNonceClient);
    private key;
    consume(scope: string, nonce: string, ttlMs: number): Promise<'ok' | 'replay'>;
}
