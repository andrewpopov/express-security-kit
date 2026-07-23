"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultKeyGenerator = exports.resolveClientIp = void 0;
exports.ipKey = ipKey;
exports.verifiedIdentityKey = verifiedIdentityKey;
exports.ipKeyResolved = ipKeyResolved;
exports.verifiedIdentityKeyResolved = verifiedIdentityKeyResolved;
exports.decodedJwtKey = decodedJwtKey;
exports.hmacBodyFieldKey = hmacBodyFieldKey;
const node_crypto_1 = require("node:crypto");
const resolveClientIp_1 = require("../ip/resolveClientIp");
var resolveClientIp_2 = require("../ip/resolveClientIp");
Object.defineProperty(exports, "resolveClientIp", { enumerable: true, get: function () { return resolveClientIp_2.resolveClientIp; } });
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
function ipKey(req) {
    return `ip:${req.ip ?? 'unknown'}`;
}
/**
 * Verified-identity key: `user:<principalId>` when a verified security context
 * is present, else falls back to {@link ipKey}. This is the CORRECT fair-share
 * strategy, but only for limiters mounted AFTER auth middleware has populated
 * `req.securityContext` — before that, principalId is absent and this degrades
 * to per-IP keying.
 */
function verifiedIdentityKey(req) {
    const principalId = req.securityContext?.principalId;
    if (principalId) {
        return `user:${principalId}`;
    }
    return ipKey(req);
}
/**
 * Back-compat alias for {@link verifiedIdentityKey}; also the createRateLimiter
 * default.
 */
exports.defaultKeyGenerator = verifiedIdentityKey;
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
function ipKeyResolved(options = {}) {
    return (req) => `ip:${(0, resolveClientIp_1.resolveClientIp)(req, options) || 'unknown'}`;
}
/**
 * Factory for {@link verifiedIdentityKey}, but falling back to
 * {@link ipKeyResolved} instead of plain {@link ipKey}. Same opt-in contract
 * as {@link ipKeyResolved}: no options means the default (least-trusting)
 * resolution, not a behavior change for anyone not passing this factory
 * `trustCloudflare`/`trustXff`.
 */
function verifiedIdentityKeyResolved(options = {}) {
    const fallback = ipKeyResolved(options);
    return (req) => {
        const principalId = req.securityContext?.principalId;
        if (principalId) {
            return `user:${principalId}`;
        }
        return fallback(req);
    };
}
/** Base64url-decode a single JWT segment. Returns undefined on any problem. */
function decodeSegment(segment) {
    try {
        const json = Buffer.from(segment, 'base64url').toString('utf8');
        if (!json)
            return undefined;
        const parsed = JSON.parse(json);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            return undefined;
        }
        return parsed;
    }
    catch {
        return undefined;
    }
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
function decodedJwtKey(opts = {}) {
    const claim = opts.claim ?? 'sub';
    const header = (opts.header ?? 'authorization').toLowerCase();
    const prefix = opts.prefix ?? 'user';
    const fallback = opts.fallback ?? ipKey;
    /** Run the configured fallback, but never let IT throw either. */
    const safeFallback = (req) => {
        try {
            return fallback(req);
        }
        catch {
            // Final guard: even a throwing custom fallback must not break the
            // never-throws guarantee. ipKey is total (never throws).
            return ipKey(req);
        }
    };
    return (req) => {
        try {
            const raw = req.headers?.[header];
            const headerValue = Array.isArray(raw) ? raw[0] : raw;
            if (typeof headerValue !== 'string' || headerValue.length === 0) {
                return safeFallback(req);
            }
            const match = /^Bearer\s+(.+)$/i.exec(headerValue.trim());
            const token = match ? match[1] : headerValue.trim();
            const parts = token.split('.');
            if (parts.length !== 3) {
                return safeFallback(req);
            }
            const payload = decodeSegment(parts[1]);
            const value = payload?.[claim];
            if (typeof value === 'string' && value.length > 0) {
                return `${prefix}:${value}`;
            }
            if (typeof value === 'number') {
                return `${prefix}:${value}`;
            }
            return safeFallback(req);
        }
        catch {
            // Defense in depth: this strategy must never throw.
            return safeFallback(req);
        }
    };
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
function hmacBodyFieldKey(opts) {
    const { field, secret } = opts;
    // Fail fast at WIRING time (not per-request): a missing/empty secret would
    // make the HMAC keys forgeable and silently weaken the per-account limiter.
    // This throws when you build the limiter, never inside the request path.
    if (typeof secret !== 'string' || secret.length === 0) {
        throw new Error('hmacBodyFieldKey: a non-empty `secret` is required');
    }
    if (typeof field !== 'string' || field.length === 0) {
        throw new Error('hmacBodyFieldKey: a non-empty `field` is required');
    }
    const prefix = opts.prefix ?? 'acct';
    const canonicalize = opts.canonicalize ?? ((raw) => raw);
    const fallback = opts.fallback ?? ipKey;
    /** Run the configured fallback, but never let IT throw either. */
    const safeFallback = (req) => {
        try {
            return fallback(req);
        }
        catch {
            // Final guard: even a throwing custom fallback must not break the
            // never-throws guarantee. ipKey is total (never throws).
            return ipKey(req);
        }
    };
    return (req) => {
        try {
            const body = req.body;
            const value = body?.[field];
            if (typeof value !== 'string' || value.length === 0) {
                return safeFallback(req);
            }
            const hmacHex = (0, node_crypto_1.createHmac)('sha256', secret).update(canonicalize(value)).digest('hex');
            return `${prefix}:${hmacHex}`;
        }
        catch {
            // Defense in depth: this strategy must never throw.
            return safeFallback(req);
        }
    };
}
