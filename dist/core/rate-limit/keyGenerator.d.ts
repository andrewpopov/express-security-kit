import type { SecurityRequest } from '../http';
import { ClientIpResolutionOptions } from '../ip/resolveClientIp';
export type { ClientIpResolutionOptions } from '../ip/resolveClientIp';
export { resolveClientIp } from '../ip/resolveClientIp';
export type KeyGeneratorCore<Req extends SecurityRequest = SecurityRequest> = (req: Req) => string;
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
export declare function ipKey<Req extends SecurityRequest = SecurityRequest>(req: Req): string;
/**
 * Verified-identity key: `user:<principalId>` when a verified security context
 * is present, else falls back to {@link ipKey}. This is the CORRECT fair-share
 * strategy, but only for limiters mounted AFTER auth middleware has populated
 * `req.securityContext` — before that, principalId is absent and this degrades
 * to per-IP keying.
 */
export declare function verifiedIdentityKey<Req extends SecurityRequest = SecurityRequest>(req: Req): string;
/**
 * Back-compat alias for {@link verifiedIdentityKey}; also the createRateLimiter
 * default.
 */
export declare const defaultKeyGenerator: KeyGeneratorCore;
/**
 * Factory for {@link ipKey}, but keyed on {@link resolveClientIp} instead of
 * `req.ip` alone — OPT-IN (see {@link ClientIpResolutionOptions}) so an
 * adopter behind Cloudflare/cloudflared can key on the real caller instead of
 * every request collapsing onto one shared edge IP, or trust the last
 * `X-Forwarded-For` hop rather than the spoofable first one. Calling this
 * with no options is intentionally NOT equivalent to plain {@link ipKey}: it
 * runs the input through {@link resolveClientIp}'s own normalization even in
 * the no-trust-flags case. Existing consumers who don't opt in are
 * unaffected — they keep using {@link ipKey}/{@link defaultKeyGenerator}
 * untouched.
 */
export declare function ipKeyResolved<Req extends SecurityRequest = SecurityRequest>(options?: ClientIpResolutionOptions): KeyGeneratorCore<Req>;
/**
 * Factory for {@link verifiedIdentityKey}, but falling back to
 * {@link ipKeyResolved} instead of plain {@link ipKey}. Same opt-in contract
 * as {@link ipKeyResolved}: no options means the default (least-trusting)
 * resolution, not a behavior change for anyone not passing this factory
 * `trustCloudflare`/`trustXff`.
 */
export declare function verifiedIdentityKeyResolved<Req extends SecurityRequest = SecurityRequest>(options?: ClientIpResolutionOptions): KeyGeneratorCore<Req>;
export interface DecodedJwtKeyOptionsCore<Req extends SecurityRequest = SecurityRequest> {
    /** JWT claim to key on. Default 'sub'. */
    claim?: string;
    /** Header carrying the Bearer token. Default 'authorization'. */
    header?: string;
    /** Prefix for the emitted key. Default 'user'. */
    prefix?: string;
    /** Key generator used when no usable claim can be extracted. Default ipKey. */
    fallback?: KeyGeneratorCore<Req>;
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
export declare function decodedJwtKey<Req extends SecurityRequest = SecurityRequest>(opts?: DecodedJwtKeyOptionsCore<Req>): KeyGeneratorCore<Req>;
export interface HmacBodyFieldKeyOptionsCore<Req extends SecurityRequest = SecurityRequest> {
    /** Request-body field to key on, e.g. 'email'. */
    field: string;
    /** HMAC-SHA256 secret. */
    secret: string;
    /** Prefix for the emitted key. Default 'acct'. */
    prefix?: string;
    /**
     * Normalize the raw field value before hashing. Default identity — pass
     * one that matches the same canonical form your auth lookup uses (e.g.
     * lowercase + trim an email), so the rate-limit key lines up with the
     * account the login attempt is actually against.
     */
    canonicalize?: (raw: string) => string;
    /** Key generator used when the field is missing/non-string. Default ipKey. */
    fallback?: KeyGeneratorCore<Req>;
}
/**
 * Factory for a Tier-2 PER-ACCOUNT keying strategy for a FAILED-login
 * limiter: keys on an HMAC-SHA256 of a request-body field (typically the
 * login identifier, e.g. 'email'), so many distinct IPs credential-stuffing
 * the SAME account still land in one shared bucket instead of each getting
 * their own budget. Intended to be paired with `skipSuccessful` so
 * successful logins don't consume the budget — only failed attempts against
 * a given account count.
 *
 * The field value is run through `canonicalize` (default identity — pass a
 * canonicalizer matching your auth lookup's normalization, e.g.
 * lowercase+trim an email) BEFORE hashing, so the key aligns with the same
 * account across superficial input variants. It is then HMAC'd — never used
 * raw — so the rate-limit store never holds a plaintext email/identifier,
 * only an opaque digest keyed on `secret`.
 *
 * Reads the body defensively: `SecurityRequest` does not type `body`, so it
 * is accessed via a narrowed cast rather than `any`. NEVER throws — any
 * failure (missing/non-string field, hashing error, a throwing fallback) is
 * caught and degrades to {@link ipKey}, mirroring {@link decodedJwtKey}'s
 * total-function discipline.
 */
export declare function hmacBodyFieldKey<Req extends SecurityRequest = SecurityRequest>(opts: HmacBodyFieldKeyOptionsCore<Req>): KeyGeneratorCore<Req>;
