import type { Request } from 'express';
export type KeyGenerator = (req: Request) => string;
/**
 * Coarse per-IP key. Use for the EARLY flood/DoS tier (Tier 1) mounted before
 * auth.
 *
 * WARNING: `req.ip` is only meaningful when it reflects the real client. Behind
 * a cloudflared tunnel or any reverse proxy that terminates the connection,
 * every request can share ONE source IP — which collapses ALL callers into a
 * SINGLE rate-limit bucket. Configure Express `trust proxy` correctly so
 * `req.ip` is the forwarded client address.
 */
export declare function ipKey(req: Request): string;
/**
 * Verified-identity key: `user:<principalId>` when a verified security context
 * is present, else falls back to {@link ipKey}. This is the CORRECT fair-share
 * strategy, but only for limiters mounted AFTER auth middleware has populated
 * `req.securityContext` — before that, principalId is absent and this degrades
 * to per-IP keying.
 */
export declare function verifiedIdentityKey(req: Request): string;
/**
 * Back-compat alias for {@link verifiedIdentityKey}; also the createRateLimiter
 * default.
 */
export declare const defaultKeyGenerator: KeyGenerator;
export interface DecodedJwtKeyOptions {
    /** JWT claim to key on. Default 'sub'. */
    claim?: string;
    /** Header carrying the Bearer token. Default 'authorization'. */
    header?: string;
    /** Prefix for the emitted key. Default 'user'. */
    prefix?: string;
    /** Key generator used when no usable claim can be extracted. Default ipKey. */
    fallback?: KeyGenerator;
}
/**
 * Factory for a PRE-AUTH keying strategy that DECODES (does NOT verify) the
 * Bearer JWT and keys on a claim (default 'sub').
 *
 * Why decode-without-verify is legitimate here: rate limiting runs BEFORE auth
 * verification, so we cannot yet trust the token — but keying on the claimed
 * subject still gives per-caller fairness for the overwhelmingly common case of
 * honest clients, and forged tokens are rejected downstream with 401 before
 * they reach the backend, so they cost nothing but a cache miss.
 *
 * TRADEOFF: a forged token can claim a VICTIM's id and thereby consume the
 * victim's bucket. Therefore `decodedJwtKey()` must ONLY be used BEHIND a
 * coarse per-IP flood tier (Tier 1), never as the sole limiter guarding
 * sensitive fair-share. When you can key after auth, prefer
 * {@link verifiedIdentityKey}.
 *
 * NEVER throws on a malformed/missing/garbage token — it silently falls back.
 */
export declare function decodedJwtKey(opts?: DecodedJwtKeyOptions): KeyGenerator;
