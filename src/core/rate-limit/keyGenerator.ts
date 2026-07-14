import type { SecurityRequest } from '../http';
import {
  resolveClientIp,
  ClientIpResolutionOptions,
} from '../ip/resolveClientIp';
export type { ClientIpResolutionOptions } from '../ip/resolveClientIp';
export { resolveClientIp } from '../ip/resolveClientIp';

export type KeyGeneratorCore<Req extends SecurityRequest = SecurityRequest> = (
  req: Req,
) => string;

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
export function ipKey<Req extends SecurityRequest = SecurityRequest>(
  req: Req,
): string {
  return `ip:${req.ip ?? 'unknown'}`;
}

/**
 * Verified-identity key: `user:<principalId>` when a verified security context
 * is present, else falls back to {@link ipKey}. This is the CORRECT fair-share
 * strategy, but only for limiters mounted AFTER auth middleware has populated
 * `req.securityContext` — before that, principalId is absent and this degrades
 * to per-IP keying.
 */
export function verifiedIdentityKey<Req extends SecurityRequest = SecurityRequest>(
  req: Req,
): string {
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
export const defaultKeyGenerator: KeyGeneratorCore = verifiedIdentityKey;

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
export function ipKeyResolved<Req extends SecurityRequest = SecurityRequest>(
  options: ClientIpResolutionOptions = {},
): KeyGeneratorCore<Req> {
  return (req: Req): string => `ip:${resolveClientIp(req, options) || 'unknown'}`;
}

/**
 * Factory for {@link verifiedIdentityKey}, but falling back to
 * {@link ipKeyResolved} instead of plain {@link ipKey}. Same opt-in contract
 * as {@link ipKeyResolved}: no options means the default (least-trusting)
 * resolution, not a behavior change for anyone not passing this factory
 * `trustCloudflare`/`trustXff`.
 */
export function verifiedIdentityKeyResolved<Req extends SecurityRequest = SecurityRequest>(
  options: ClientIpResolutionOptions = {},
): KeyGeneratorCore<Req> {
  const fallback = ipKeyResolved<Req>(options);
  return (req: Req): string => {
    const principalId = req.securityContext?.principalId;
    if (principalId) {
      return `user:${principalId}`;
    }
    return fallback(req);
  };
}

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

/** Base64url-decode a single JWT segment. Returns undefined on any problem. */
function decodeSegment(segment: string): Record<string, unknown> | undefined {
  try {
    const json = Buffer.from(segment, 'base64url').toString('utf8');
    if (!json) return undefined;
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return undefined;
    }
    return parsed as Record<string, unknown>;
  } catch {
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
export function decodedJwtKey<Req extends SecurityRequest = SecurityRequest>(
  opts: DecodedJwtKeyOptionsCore<Req> = {},
): KeyGeneratorCore<Req> {
  const claim = opts.claim ?? 'sub';
  const header = (opts.header ?? 'authorization').toLowerCase();
  const prefix = opts.prefix ?? 'user';
  const fallback = opts.fallback ?? ipKey;

  /** Run the configured fallback, but never let IT throw either. */
  const safeFallback = (req: Req): string => {
    try {
      return fallback(req);
    } catch {
      // Final guard: even a throwing custom fallback must not break the
      // never-throws guarantee. ipKey is total (never throws).
      return ipKey(req);
    }
  };

  return (req: Req): string => {
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
    } catch {
      // Defense in depth: this strategy must never throw.
      return safeFallback(req);
    }
  };
}
