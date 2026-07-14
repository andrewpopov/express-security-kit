import type { SecurityRequest } from '../http';
import { normalizeIp } from '../api-key/normalizeIp';

/**
 * Caps the resolved IP string length. A header is attacker-controlled input;
 * without a cap a hostile `X-Forwarded-For`/`Cf-Connecting-Ip` value could be
 * used to smuggle an arbitrarily long string into a rate-limit bucket key
 * (store memory pressure, log bloat). 64 chars comfortably fits any real IPv4
 * or IPv6 literal (the longest valid IPv6 text form is 45 chars) with room to
 * spare — matches the cap rouge's `clientIpFromRequest` uses.
 */
const MAX_IP_LENGTH = 64;

/**
 * Caps the User-Agent slice folded into the UA-fallback key (see
 * `uaFallback` below). Matches bewks's `getClientId` exactly (`userAgent
 * .slice(0, 40)`) — the whole point of this option is to reproduce bewks's
 * bucket keys byte-for-byte, not to invent a new scheme.
 */
const MAX_UA_FALLBACK_LENGTH = 40;

export interface ClientIpResolutionOptions {
  /**
   * Trust the `Cf-Connecting-Ip` header set by Cloudflare's edge. Cloudflare
   * OVERWRITES this header on every request it proxies, so a client cannot
   * forge it — it is authoritative when the deployment actually sits behind
   * Cloudflare (or cloudflared). Default false: a service NOT behind
   * Cloudflare must not trust a header any client could otherwise inject.
   */
  trustCloudflare?: boolean;
  /**
   * Trust the LAST hop of `X-Forwarded-For` — the entry appended by the
   * nearest trusted reverse proxy — as the client IP. The FIRST hop is
   * whatever the client sent and is trivially spoofable; only the last hop
   * (assuming exactly one proxy sits in front, which appends rather than
   * trusts an inbound XFF) is proxy-controlled. Default false: taking any XFF
   * value on trust is only safe when a reverse proxy in the request path is
   * known to overwrite/append rather than pass the client's header through
   * verbatim.
   */
  trustXff?: boolean;
  /**
   * GAP 1 (bewks `getClientId` / `cloudflareSecurityUtils.getClientIP`,
   * ported so bewks can adopt this kit without regressing its rate limiter).
   *
   * When no trusted IP is available — `trustCloudflare`/`trustXff` are off,
   * disagree, or the corresponding header is absent — return a
   * User-Agent-derived fingerprint (`untrusted:<first 40 chars of UA, or
   * "no-ua">`) INSTEAD of falling back to `req.ip`/the socket peer.
   *
   * bewks's rationale, preserved verbatim: a spoofable IP is worse than no
   * IP for a rate-limit bucket key, because an attacker can rotate it on
   * every request to mint a fresh bucket each time and bypass the limiter
   * entirely. A User-Agent string is still attacker-controlled, but it is
   * NOT a single header an attacker is already forging to defeat this exact
   * check — using it raises the cost of the bypass instead of leaving the
   * door open. This mirrors bewks's `getClientId`: `trusted` (there, "did
   * `cf-connecting-ip` resolve") gates between `clientInfo.ip` and
   * `` `untrusted:${userAgent.slice(0, 40) || 'no-ua'}` ``.
   *
   * Default false: a consumer that doesn't opt in keeps falling back to
   * `req.ip` (or the trusted peer, see `trustedPeers`), which is what keeps
   * default (no-config) behavior byte-identical to pre-1.5.0.
   */
  uaFallback?: boolean;
  /**
   * GAP 2 (fidash `get_client_ip`/`is_trusted_proxy`, ported as a PATTERN —
   * fidash is Python and will never consume this kit).
   *
   * Gates `trustCloudflare`/`trustXff` behind WHO actually opened the TCP
   * connection, not just whether the flags are on. Without this gate, a
   * consumer that sets `trustCloudflare`/`trustXff` trusts those headers
   * from ANY socket that can reach the Express port — including a direct
   * LAN/localhost attacker who never went through Cloudflare or the reverse
   * proxy, and who can therefore forge `Cf-Connecting-Ip` or
   * `X-Forwarded-For` outright.
   *
   * When set (even to an empty array — that still trusts loopback, useful
   * for local dev), a request's forwarding headers are honored ONLY when
   * `req.socket.remoteAddress` (normalized via `normalizeIp`, so
   * `::ffff:`-mapped and `::1` peers compare correctly) is:
   *   - the IPv4/IPv6 loopback address, or
   *   - an exact match, or a match inside a CIDR block, in this list.
   *
   * Otherwise the headers are ignored entirely and resolution falls back to
   * the peer address itself (or the UA fingerprint, if `uaFallback` is also
   * on) — mirroring fidash's `get_client_ip`, which returns the raw
   * `request.client.host` unchanged when the peer isn't a trusted proxy.
   *
   * Default `undefined` (off): a consumer that doesn't opt in gets no
   * peer-gating at all, which is what keeps default (no-config) behavior —
   * and existing `trustCloudflare`/`trustXff` consumers' behavior — exactly
   * as it was pre-1.5.0.
   *
   * Entries may be a bare IPv4/IPv6 literal (e.g. `'10.0.0.7'`) or an IPv4
   * CIDR block (e.g. `'10.0.0.0/8'`). IPv6 CIDR ranges are not supported —
   * list IPv6 trusted peers as exact literals. This is a narrower CIDR
   * matcher than fidash's (which uses Python's full `ipaddress` module); it
   * covers the fleet's actual trusted-proxy shapes (single hosts, IPv4
   * ranges) without pulling in a CIDR dependency.
   */
  trustedPeers?: readonly string[];
}

/** First value when a header is duplicated into an array; else the header itself. */
function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** The final (right-most / edge-appended) hop of a comma-separated XFF value. */
function lastXffHop(value: string): string | undefined {
  const hops = value.split(',');
  return hops[hops.length - 1];
}

/** Normalize + length-cap a candidate IP; `''` when the candidate is unusable. */
function clean(candidate: string | undefined): string {
  return normalizeIp(candidate).slice(0, MAX_IP_LENGTH);
}

/**
 * bewks's UA-derived fallback key, reproduced byte-for-byte: `getClientId`
 * in bewks's `rateLimiter.ts` builds `` `untrusted:${userAgent.slice(0, 40)
 * || 'no-ua'}` `` from `request.headers.get('user-agent')`. Deliberately NOT
 * run through `normalizeIp`/`clean` — those are IP-specific (lowercase,
 * `::ffff:` stripping) and would silently diverge from bewks's exact string.
 */
function uaFallbackKey(headers: SecurityRequest['headers']): string {
  const uaRaw = firstHeaderValue(headers['user-agent']);
  const ua = typeof uaRaw === 'string' ? uaRaw.slice(0, MAX_UA_FALLBACK_LENGTH) : '';
  return `untrusted:${ua || 'no-ua'}`;
}

/** Parse a dotted-quad IPv4 literal into a 32-bit unsigned integer, or `null` if invalid. */
function ipv4ToInt(ip: string): number | null {
  const octets = ip.split('.');
  if (octets.length !== 4) return null;
  let result = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const value = Number(octet);
    if (value > 255) return null;
    result = (result << 8) | value;
  }
  return result >>> 0;
}

/** Whether `ip` (an IPv4 literal) falls inside `cidr` (`'a.b.c.d/nn'`). `false` on any parse failure. */
function isIpv4InCidr(ip: string, cidr: string): boolean {
  const slashIndex = cidr.indexOf('/');
  if (slashIndex === -1) return false;
  const base = cidr.slice(0, slashIndex);
  const prefixLength = Number(cidr.slice(slashIndex + 1));
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) return false;

  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;

  const mask = prefixLength === 0 ? 0 : (~0 << (32 - prefixLength)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/**
 * Whether `peer` (already `clean()`-normalized) is trusted per fidash's
 * `is_trusted_proxy`: the canonical loopback address, or an exact/CIDR match
 * against `trustedPeers`. Entries are normalized with `normalizeIp` before
 * an exact-match comparison so a `::ffff:`-mapped or differently-cased
 * config entry still matches.
 */
function isTrustedPeer(peer: string, trustedPeers: readonly string[]): boolean {
  if (!peer) return false;
  if (peer === '127.0.0.1') return true; // IPv4 loopback, and IPv6 ::1 post-clean().
  for (const entry of trustedPeers) {
    const candidate = entry.trim();
    if (!candidate) continue;
    if (candidate.includes('/')) {
      if (isIpv4InCidr(peer, candidate)) return true;
    } else if (normalizeIp(candidate) === peer) {
      return true;
    }
  }
  return false;
}

/**
 * Resolve the trusted client IP for a request, per an OPT-IN trust
 * precedence (ROG-1094, ported from rouge's `clientIpFromRequest` — the
 * fleet's reference implementation):
 *
 *   0. Peer gate (`trustedPeers`, opt-in): when set, steps 1-2 below are only
 *      attempted if `req.socket.remoteAddress` is loopback or in the
 *      configured set — otherwise the headers are skipped entirely, closing
 *      the direct-connection spoof fidash's `get_client_ip` guards against.
 *   1. `Cf-Connecting-Ip`, when `trustCloudflare` is set (and the peer gate,
 *      if engaged, passed).
 *   2. The LAST `X-Forwarded-For` hop, when `trustXff` is set (and the peer
 *      gate, if engaged, passed) — never the first hop, which is
 *      client-controlled and the whole point of the bypass this closes.
 *   3. A User-Agent-derived fingerprint, when `uaFallback` is set and no
 *      trusted IP was found in steps 1-2 — instead of falling back to a
 *      spoofable address (bewks's `getClientId` fallback).
 *   4. The socket peer address, when `trustedPeers` is engaged and no
 *      trusted IP/UA fallback applied — mirrors fidash's raw-peer fallback
 *      rather than trusting `req.ip` (which is itself derived from headers
 *      under Express's own trust-proxy setting).
 *   5. `req.ip` — Express's own trust-proxy-aware resolution. This is the
 *      ONLY step that runs with NO options set, which is what keeps default
 *      (no-config) behavior identical to the pre-existing `ipKey`. Unlike
 *      rouge's raw `req.socket.remoteAddress` fallback, this kit sits on top
 *      of Express, which already performs the trust-proxy-aware socket
 *      resolution into `req.ip` — re-deriving it from the raw socket here
 *      would just duplicate that logic and could disagree with it.
 *
 * All four options (`trustCloudflare`, `trustXff`, `uaFallback`,
 * `trustedPeers`) default to off/`undefined`: enabling any of them changes
 * which requests collapse into the same rate-limit bucket, so silently
 * trusting a header (or gating on a peer, or diverting to a UA fingerprint)
 * for every existing consumer would be its own bug. A caller must opt in
 * knowing which (if any) reverse proxy actually sits in front of it.
 *
 * NEVER throws: garbage/absent headers, options, or socket degrade to
 * `req.ip` (or `''` if that too is absent) rather than crashing the caller —
 * the limiter this feeds must keep failing open, never closed.
 */
export function resolveClientIp<Req extends SecurityRequest = SecurityRequest>(
  req: Req,
  options: ClientIpResolutionOptions = {},
): string {
  try {
    const headers = req?.headers ?? {};
    const peerGateEngaged = options.trustedPeers !== undefined;
    const peer = clean(req?.socket?.remoteAddress);
    const peerTrusted = !peerGateEngaged || isTrustedPeer(peer, options.trustedPeers ?? []);

    if (peerTrusted) {
      if (options.trustCloudflare) {
        const cf = clean(firstHeaderValue(headers['cf-connecting-ip']));
        if (cf) return cf;
      }

      if (options.trustXff) {
        const xffRaw = firstHeaderValue(headers['x-forwarded-for']);
        if (typeof xffRaw === 'string' && xffRaw.length > 0) {
          const lastHop = clean(lastXffHop(xffRaw));
          if (lastHop) return lastHop;
        }
      }
    }

    if (options.uaFallback) {
      return uaFallbackKey(headers);
    }

    if (peerGateEngaged) {
      return peer;
    }

    return clean(req?.ip);
  } catch {
    // Defense in depth: a hostile/malformed req must never crash the caller.
    return '';
  }
}
