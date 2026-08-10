import { createHash } from 'node:crypto';

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

interface NonceEntry {
  expiresAt: number;
}

export interface MemoryNonceStoreOptions {
  /** Cleanup timer interval (ms). Default 60_000. */
  cleanupIntervalMs?: number;
  /** Max tracked nonces before drop-oldest eviction. Default 100_000. */
  maxTrackedNonces?: number;
  /** Injectable clock for tests. Default Date.now. */
  now?: () => number;
}

const DEFAULT_CLEANUP_INTERVAL_MS = 60_000;
const DEFAULT_MAX_TRACKED_NONCES = 100_000;

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
export class MemoryNonceStore implements NonceStore {
  private readonly entries = new Map<string, NonceEntry>();
  private readonly cleanupIntervalMs: number;
  private readonly maxTrackedNonces: number;
  private readonly clock: () => number;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: MemoryNonceStoreOptions = {}) {
    this.cleanupIntervalMs =
      options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL_MS;
    const maxTrackedNonces =
      options.maxTrackedNonces ?? DEFAULT_MAX_TRACKED_NONCES;
    if (!Number.isInteger(maxTrackedNonces) || maxTrackedNonces <= 0) {
      // A non-positive cap would evict every nonce immediately, silently
      // disabling replay protection. A fractional cap has no coherent meaning
      // either — the reservation check would admit ceil(cap) entries while the
      // configured value reads as a lower bound. Reject both outright.
      throw new Error(
        'MemoryNonceStore: maxTrackedNonces must be a positive integer',
      );
    }
    this.maxTrackedNonces = maxTrackedNonces;
    this.clock = options.now ?? Date.now;
    this.startTimer();
  }

  private startTimer(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
    this.timer.unref?.();
  }

  private storageKey(scope: string, nonce: string): string {
    const hash = createHash('sha256').update(nonce).digest('hex');
    return `${scope}:${hash}`;
  }

  async consume(
    scope: string,
    nonce: string,
    ttlMs: number,
  ): Promise<'ok' | 'replay'> {
    const now = this.clock();
    const key = this.storageKey(scope, nonce);

    const existing = this.entries.get(key);
    if (existing && existing.expiresAt > now) {
      return 'replay';
    }

    // New (or expired) — drop any stale entry for this exact key first so it
    // doesn't count twice against capacity below.
    this.entries.delete(key);
    // Reserve room for the entry BEFORE inserting it: a throw here must leave
    // the store exactly as it was, never with a dangling over-cap entry.
    this.reserveCapacity(now);
    this.entries.set(key, { expiresAt: now + ttlMs });
    return 'ok';
  }

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
  private reserveCapacity(now: number): void {
    if (this.entries.size < this.maxTrackedNonces) return;

    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
      }
    }

    if (this.entries.size >= this.maxTrackedNonces) {
      throw new Error(
        'MemoryNonceStore capacity exceeded (all tracked nonces live)',
      );
    }
  }

  private cleanup(): void {
    const now = this.clock();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
      }
    }
  }

  /** Alias of dispose() for ergonomic test teardown. */
  stop(): void {
    this.dispose();
  }

  dispose(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** Test/introspection helper. */
  get size(): number {
    return this.entries.size;
  }
}
