/**
 * Replay-protection store. `consume` atomically records a nonce and reports
 * whether it was already present (a replay).
 */
export interface NonceStore {
    /**
     * Record `nonce` under `scope` with a time-to-live of `ttlMs`.
     * - `'ok'`     — first time this (scope, nonce) is seen; recorded.
     * - `'replay'` — already recorded within its TTL; the request must be rejected.
     * A thrown/rejected call means the store is UNAVAILABLE — the verifier fails
     * CLOSED (rejects the request) rather than allowing a possible replay.
     */
    consume(scope: string, nonce: string, ttlMs: number): Promise<'ok' | 'replay'>;
    /** Release resources (timers). Safe to call more than once. */
    dispose?(): void;
}
export interface MemoryNonceStoreOptions {
    /** Cleanup timer interval (ms). Default 60_000. */
    cleanupIntervalMs?: number;
    /** Max tracked nonces before drop-oldest eviction. Default 100_000. */
    maxTrackedNonces?: number;
    /** Injectable clock for tests. Default Date.now. */
    now?: () => number;
}
/**
 * In-memory, single-process nonce store.
 *
 * The nonce is sha256-hashed and stored under `${scope}:${hash}` so raw nonces
 * never sit in memory and keys are fixed-length. Entries expire after `ttlMs`;
 * an `.unref()`'d timer sweeps stale entries. At the `maxTrackedNonces` cap the
 * store prunes expired entries and, if still full of LIVE nonces, FAILS CLOSED
 * (throws) rather than evicting a live nonce — evicting one would reopen a
 * replay window.
 *
 * IMPORTANT: this is PER-PROCESS. In a multi-instance / clustered deployment it
 * provides NO cross-instance replay protection — a replay routed to a different
 * instance would not be detected. Inject a persistent shared store (Prisma,
 * Redis, etc.) implementing {@link NonceStore} for those deployments.
 */
export declare class MemoryNonceStore implements NonceStore {
    private readonly entries;
    private readonly cleanupIntervalMs;
    private readonly maxTrackedNonces;
    private readonly clock;
    private timer;
    constructor(options?: MemoryNonceStoreOptions);
    private startTimer;
    private storageKey;
    consume(scope: string, nonce: string, ttlMs: number): Promise<'ok' | 'replay'>;
    /**
     * Ensure there is room for one more entry WITHOUT ever evicting a live nonce
     * (evicting a within-TTL nonce would let its request be replayed). Only when
     * the store is already at/over its cap do we prune everything that has
     * expired; if it is STILL at/over cap afterward, every remaining entry is
     * live — so we THROW rather than evict. Called BEFORE the new entry is
     * inserted, so a rejected nonce never grows the store past `maxTrackedNonces`.
     * The verifier maps a store throw to `store_error` → 401, i.e. it fails
     * CLOSED.
     */
    private reserveCapacity;
    private cleanup;
    /** Alias of dispose() for ergonomic test teardown. */
    stop(): void;
    dispose(): void;
    /** Test/introspection helper. */
    get size(): number;
}
