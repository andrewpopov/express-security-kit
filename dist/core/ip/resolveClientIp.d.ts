import type { SecurityRequest } from '../http';
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
export declare function resolveClientIp<Req extends SecurityRequest = SecurityRequest>(req: Req, options?: ClientIpResolutionOptions): string;
