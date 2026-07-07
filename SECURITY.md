# Security model

`@andrewpopov/express-security-kit` owns security **machinery**; the
consuming service owns **policy** (secrets, persistence, what's auditable).
This is a per-pillar threat model — what each module defends against, and
what it explicitly does **not**.

## Pillar-by-pillar

### Helmet preset (`createHelmetMiddleware`)

- **Defends:** common browser-side injection/clickjacking vectors via a
  strict default CSP, HSTS, and helmet's other security headers.
- **Does NOT defend against:** server-side vulnerabilities (injection, auth
  bugs, SSRF, …) — headers are a browser-side mitigation layer only. A
  misconfigured `csp.*` override can also widen the policy beyond what you
  intend; review any `overrides` you pass.

### Rate limiter (`createRateLimiter`)

- **Defends:** abusive/buggy-client request volume from a single
  key (IP or principal) — fair-share and basic flood damping.
- **Does NOT defend against:** distributed denial-of-service. **Rate limiting
  is not DoS protection** — a sufficiently distributed attacker (many IPs/keys)
  is unaffected. Put a real DDoS-mitigation layer (CDN/WAF) in front of
  anything internet-facing.
- **Fails OPEN** on a store error/outage — availability of the service is
  prioritized over the limit. A sustained store outage means requests are
  effectively unlimited until the store recovers.
- Keying is only as good as your `trust proxy` config; behind a
  connection-terminating proxy/tunnel, IP-based keys can collapse every
  caller into one bucket (see the README's IP-collapse warning).

### API-key auth (`createApiKeyAuth` / `verifyApiKey`)

- **Defends:** unauthenticated/forged-key access to protected routes;
  verifies a presented key against a service-supplied `lookup`.
- **Does NOT defend against:** a leaked valid key (this is bearer-token
  auth — anyone holding the key authenticates as it) or key management
  practices (rotation, storage) — those are the service's responsibility.
- **IP allowlist is exact-match, not CIDR-aware.** `allowedIps` does string
  equality against `req.ip`; it is not a range/subnet check, and its
  trustworthiness depends entirely on `trust proxy` being configured
  correctly (a spoofable `X-Forwarded-For` defeats it).
- **Fails CLOSED** — any failure (including a throwing `lookup`) is a
  generic 401/403; the specific reason goes only to `onFailure`, never to
  the client.

### HMAC request signing (`createRequestSigningVerifier` / `signRequest`)

- **Defends:** tampering (body/method/url) and replay of high-value
  machine-to-machine requests via an HMAC signature + single-use nonce.
- **Does NOT defend against:** a leaked signing secret (equivalent to a
  leaked API key for that scope) or a captured-and-replayed request within
  the same skew/TTL window on a nonce store that isn't shared cluster-wide
  (see replay-window semantics below).
- **Fails CLOSED** — any failure (bad signature, expired skew, replay,
  unavailable nonce store) is a generic 401.
- **Replay-window semantics:** the nonce is scoped (default
  `keyId ?? principalId ?? 'global'`) and TTL'd to the skew window
  (`maxSkewSeconds`, clamped to `[30, 900]`). A nonce is safe from replay
  ONLY within that TTL and ONLY if `nonceStore` is visible to every instance
  handling that scope's traffic — `MemoryNonceStore` is per-process and
  provides **no cross-instance replay protection** in a clustered deployment.
- The canonical string throws on a raw CR/LF in `method`/`url`/`nonce` to
  prevent the LF-delimited fields from being reinterpreted (see CHANGELOG
  0.7.0). It does not, and cannot, guarantee two DIFFERENT valid request
  tuples never share a canonical string (e.g. method is upper-cased and
  GET/HEAD always zero the body) — only that the encoding has no delimiter
  ambiguity over the normalized fields.

### Buffered audit (`AuditBuffer`, hooks)

- **Defends:** losing audit visibility to a slow/broken sink or to
  synchronous back-pressure on the request path.
- **Does NOT defend against:** data loss on a hard process crash (in-memory
  queue) or sink duplication — delivery is **at-least-once**: a transient
  sink failure re-queues and retries the WHOLE failed batch, so a sink may
  see the same event more than once. Make `sink.write` idempotent (e.g.
  upsert on `AuditEvent.id`, which defaults to `crypto.randomUUID()`).
- `record()` and hook adapters NEVER throw and never block the request path.

## Fail-open / fail-closed matrix

| Pillar | On internal error | Rationale |
|---|---|---|
| Rate limiter | **Fails OPEN** (allows the request) | A limiter/store outage must not take the service down. |
| API-key auth | **Fails CLOSED** (401/403) | An auth failure must never silently authenticate. |
| Request signing | **Fails CLOSED** (401) | Same — a signature/replay check must never silently pass. |
| Audit | **Never throws / never blocks** (fire-and-forget) | Observability must never become an outage vector. |

## Reporting a vulnerability

Please use [GitHub Security Advisories](https://github.com/andrewpopov/express-security-kit/security/advisories/new)
on this repository rather than a public issue.
