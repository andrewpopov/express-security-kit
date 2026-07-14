"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveClientIp = resolveClientIp;
const normalizeIp_1 = require("../api-key/normalizeIp");
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
/** First value when a header is duplicated into an array; else the header itself. */
function firstHeaderValue(value) {
    return Array.isArray(value) ? value[0] : value;
}
/** The final (right-most / edge-appended) hop of a comma-separated XFF value. */
function lastXffHop(value) {
    const hops = value.split(',');
    return hops[hops.length - 1];
}
/** Normalize + length-cap a candidate IP; `''` when the candidate is unusable. */
function clean(candidate) {
    return (0, normalizeIp_1.normalizeIp)(candidate).slice(0, MAX_IP_LENGTH);
}
/**
 * bewks's UA-derived fallback key, reproduced byte-for-byte: `getClientId`
 * in bewks's `rateLimiter.ts` builds `` `untrusted:${userAgent.slice(0, 40)
 * || 'no-ua'}` `` from `request.headers.get('user-agent')`. Deliberately NOT
 * run through `normalizeIp`/`clean` — those are IP-specific (lowercase,
 * `::ffff:` stripping) and would silently diverge from bewks's exact string.
 */
function uaFallbackKey(headers) {
    const uaRaw = firstHeaderValue(headers['user-agent']);
    const ua = typeof uaRaw === 'string' ? uaRaw.slice(0, MAX_UA_FALLBACK_LENGTH) : '';
    return `untrusted:${ua || 'no-ua'}`;
}
/** Parse a dotted-quad IPv4 literal into a 32-bit unsigned integer, or `null` if invalid. */
function ipv4ToInt(ip) {
    const octets = ip.split('.');
    if (octets.length !== 4)
        return null;
    let result = 0;
    for (const octet of octets) {
        if (!/^\d{1,3}$/.test(octet))
            return null;
        const value = Number(octet);
        if (value > 255)
            return null;
        result = (result << 8) | value;
    }
    return result >>> 0;
}
/** Whether `ip` (an IPv4 literal) falls inside `cidr` (`'a.b.c.d/nn'`). `false` on any parse failure. */
function isIpv4InCidr(ip, cidr) {
    const slashIndex = cidr.indexOf('/');
    if (slashIndex === -1)
        return false;
    const base = cidr.slice(0, slashIndex);
    const prefixLength = Number(cidr.slice(slashIndex + 1));
    if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32)
        return false;
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(base);
    if (ipInt === null || baseInt === null)
        return false;
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
function isTrustedPeer(peer, trustedPeers) {
    if (!peer)
        return false;
    if (peer === '127.0.0.1')
        return true; // IPv4 loopback, and IPv6 ::1 post-clean().
    for (const entry of trustedPeers) {
        const candidate = entry.trim();
        if (!candidate)
            continue;
        if (candidate.includes('/')) {
            if (isIpv4InCidr(peer, candidate))
                return true;
        }
        else if ((0, normalizeIp_1.normalizeIp)(candidate) === peer) {
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
function resolveClientIp(req, options = {}) {
    try {
        const headers = req?.headers ?? {};
        const peerGateEngaged = options.trustedPeers !== undefined;
        const peer = clean(req?.socket?.remoteAddress);
        const peerTrusted = !peerGateEngaged || isTrustedPeer(peer, options.trustedPeers ?? []);
        if (peerTrusted) {
            if (options.trustCloudflare) {
                const cf = clean(firstHeaderValue(headers['cf-connecting-ip']));
                if (cf)
                    return cf;
            }
            if (options.trustXff) {
                const xffRaw = firstHeaderValue(headers['x-forwarded-for']);
                if (typeof xffRaw === 'string' && xffRaw.length > 0) {
                    const lastHop = clean(lastXffHop(xffRaw));
                    if (lastHop)
                        return lastHop;
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
    }
    catch {
        // Defense in depth: a hostile/malformed req must never crash the caller.
        return '';
    }
}
