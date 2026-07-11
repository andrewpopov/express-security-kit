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
     * Keep the store within its cap WITHOUT ever evicting a live nonce (evicting a
     * within-TTL nonce would let its request be replayed). First prune everything
     * that has expired; if the store is STILL over capacity, every remaining entry
     * is live — so we THROW rather than evict. The verifier maps a store throw to
     * `store_error` → 401, i.e. it fails CLOSED.
     */
    private enforceCapacity;
    private cleanup;
    /** Alias of dispose() for ergonomic test teardown. */
    stop(): void;
    dispose(): void;
    /** Test/introspection helper. */
    get size(): number;
}
