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
 * Resolve the trusted client IP for a request, per an OPT-IN trust
 * precedence (ROG-1094, ported from rouge's `clientIpFromRequest` — the
 * fleet's reference implementation):
 *
 *   1. `Cf-Connecting-Ip`, when `trustCloudflare` is set.
 *   2. The LAST `X-Forwarded-For` hop, when `trustXff` is set — never the
 *      first hop, which is client-controlled and the whole point of the
 *      bypass this closes.
 *   3. `req.ip` — Express's own trust-proxy-aware resolution. This is the
 *      ONLY step that runs with no options set, which is what keeps default
 *      (no-config) behavior identical to the pre-existing `ipKey`. Unlike
 *      rouge's raw `req.socket.remoteAddress` fallback, this kit sits on top
 *      of Express, which already performs the trust-proxy-aware socket
 *      resolution into `req.ip` — re-deriving it from the raw socket here
 *      would just duplicate that logic and could disagree with it.
 *
 * Both trust flags default to false: enabling either changes which requests
 * collapse into the same rate-limit bucket, so silently trusting a header
 * for every existing consumer would be its own bug. A caller must opt in
 * knowing which (if any) reverse proxy actually sits in front of it.
 *
 * NEVER throws: garbage/absent headers or a hostile `req` degrade to `req.ip`
 * (or `''` if that too is absent) rather than crashing the caller — the
 * limiter this feeds must keep failing open, never closed.
 */
export function resolveClientIp<Req extends SecurityRequest = SecurityRequest>(
  req: Req,
  options: ClientIpResolutionOptions = {},
): string {
  try {
    const headers = req?.headers ?? {};

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

    return clean(req?.ip);
  } catch {
    // Defense in depth: a hostile/malformed req must never crash the caller.
    return '';
  }
}
