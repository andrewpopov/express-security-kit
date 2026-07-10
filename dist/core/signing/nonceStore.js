"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryNonceStore = void 0;
const node_crypto_1 = require("node:crypto");
const DEFAULT_CLEANUP_INTERVAL_MS = 60000;
const DEFAULT_MAX_TRACKED_NONCES = 100000;
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
class MemoryNonceStore {
    constructor(options = {}) {
        this.entries = new Map();
        this.cleanupIntervalMs =
            options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL_MS;
        const maxTrackedNonces = options.maxTrackedNonces ?? DEFAULT_MAX_TRACKED_NONCES;
        if (!Number.isFinite(maxTrackedNonces) || maxTrackedNonces <= 0) {
            // A non-positive cap would evict every nonce immediately, silently
            // disabling replay protection. Reject it outright.
            throw new Error('MemoryNonceStore: maxTrackedNonces must be a positive number');
        }
        this.maxTrackedNonces = maxTrackedNonces;
        this.clock = options.now ?? Date.now;
        this.startTimer();
    }
    startTimer() {
        if (this.timer)
            return;
        this.timer = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
        this.timer.unref?.();
    }
    storageKey(scope, nonce) {
        const hash = (0, node_crypto_1.createHash)('sha256').update(nonce).digest('hex');
        return `${scope}:${hash}`;
    }
    async consume(scope, nonce, ttlMs) {
        const now = this.clock();
        const key = this.storageKey(scope, nonce);
        const existing = this.entries.get(key);
        if (existing && existing.expiresAt > now) {
            return 'replay';
        }
        // New (or expired) — record it. Re-insert to refresh eviction recency.
        this.entries.delete(key);
        this.entries.set(key, { expiresAt: now + ttlMs });
        this.enforceCapacity(now);
        return 'ok';
    }
    /**
     * Keep the store within its cap WITHOUT ever evicting a live nonce (evicting a
     * within-TTL nonce would let its request be replayed). First prune everything
     * that has expired; if the store is STILL over capacity, every remaining entry
     * is live — so we THROW rather than evict. The verifier maps a store throw to
     * `store_error` → 401, i.e. it fails CLOSED.
     */
    enforceCapacity(now) {
        if (this.entries.size <= this.maxTrackedNonces)
            return;
        for (const [key, entry] of this.entries) {
            if (entry.expiresAt <= now) {
                this.entries.delete(key);
            }
        }
        if (this.entries.size > this.maxTrackedNonces) {
            throw new Error('MemoryNonceStore capacity exceeded (all tracked nonces live)');
        }
    }
    cleanup() {
        const now = this.clock();
        for (const [key, entry] of this.entries) {
            if (entry.expiresAt <= now) {
                this.entries.delete(key);
            }
        }
    }
    /** Alias of dispose() for ergonomic test teardown. */
    stop() {
        this.dispose();
    }
    dispose() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = undefined;
        }
    }
    /** Test/introspection helper. */
    get size() {
        return this.entries.size;
    }
}
exports.MemoryNonceStore = MemoryNonceStore;
