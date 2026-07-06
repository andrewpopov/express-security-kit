# Changelog

All notable changes to `@andrewpopov/express-security-kit` are documented here.

## Release-guard format

This package is released by pushing a `vX.Y.Z` git tag. A CI **release-guard**
job runs on every `v*` tag and FAILS the release unless BOTH are true:

1. The tag version (`vX.Y.Z` → `X.Y.Z`) exactly equals `version` in
   `package.json`.
2. A heading `## X.Y.Z` exists in this file.

So every release MUST: bump `package.json`, add a matching `## X.Y.Z` heading
below with the changes, commit, then tag `vX.Y.Z`. Do not tag ahead of the
CHANGELOG entry.

---

## 0.3.0

Phase 3 — OPT-IN HMAC request signing + replay protection (audit is Phase 4).

### Added

- **`createRequestSigningVerifier(config)`** — Express middleware that verifies
  an HMAC-SHA256 request signature and enforces single-use nonces. Byte-for-byte
  compatible with stoki's live scheme (locked to authoritative golden vectors).
  Resolves a static or per-key secret (`securityContext.hmacSecret`), enforces
  timestamp skew (default 300s, clamped [30, 900]), a nonce format, and a
  64-hex signature; recomputes the expected signature and compares it
  constant-time; then consumes the nonce for replay protection AFTER the
  signature is proven valid and BEFORE `next()`. **Fails CLOSED** on every
  failure — including an unavailable nonce store — with a generic 401; the
  reason goes only to `onFailure`.
- **`signRequest(input)` / `buildCanonicalString(input)` / `sha256Hex(input)`**
  — client/service helpers to produce compatible signatures and headers
  (`X-Timestamp`, `X-Nonce`, `X-Signature`). The canonical string is five
  LF-joined lines: METHOD, url, timestampMs, nonce, sha256hex(body) (GET/HEAD →
  sha256hex('')).
- **`NonceStore` interface + `MemoryNonceStore`** — replay store keyed by
  `${scope}:sha256(nonce)` with per-entry TTL, an `unref`'d cleanup timer, a cap
  with drop-oldest eviction, and `stop()`/`dispose()`. Documented as PER-PROCESS
  — multi-instance deployments MUST inject a persistent shared store (Prisma /
  Redis) implementing `NonceStore`. At capacity, `MemoryNonceStore` prunes
  expired entries and, if still full of LIVE nonces, FAILS CLOSED (throws →
  verifier returns 401) rather than evicting a live nonce — evicting one would
  reopen a replay window. A non-positive `maxTrackedNonces` is rejected at
  construction. The verifier proceeds only on an explicit `'ok'` from the store;
  any other result fails closed.
- `SecurityContext` gained an optional `hmacSecret` field (populated by an
  api-key `onAuthenticated` hook) for per-key signing; the Express `Request`
  augmentation gained `rawBody` (captured by an express.json `verify` hook), the
  preferred body source for signature verification.

## 0.2.0

Phase 2 — API-key authentication (the verifier only; HMAC request signing is
Phase 3, audit is Phase 4).

### Added

- **`createApiKeyAuth(config)`** — Express API-key verifier. Extracts the key
  (Bearer or a custom header), enforces a required prefix, checks constant-time
  static bootstrap keys before DB lookup, hashes + looks up DB-backed keys,
  re-verifies the stored hash (defense in depth), and enforces expiry and an
  optional IP allowlist (with `*` wildcard). Sets `req.securityContext` — either
  a default `apiKey`/`service` context or one minted by an async
  `onAuthenticated` hook. **Fails CLOSED**: every failure (including a throwing
  `lookup`) returns a GENERIC 401/403; the specific reason goes only to the
  `onFailure` audit hook, never to the client.
- **Hashers** — `sha256Hasher()` and `scopedHmacHasher(secret, scope)` (exact
  smarthome `HMAC-SHA256(secret:scope, rawKey)` format), plus
  `timingSafeEqualHex(a, b)` — a constant-time hex/ASCII compare that returns
  false on length mismatch without an early-out timing leak and never throws.
- **`requireScope(predicate, opts?)`** — a tiny guard-builder that runs a
  service-provided policy predicate against `req.securityContext`. The predicate
  MUST be SYNCHRONOUS and return a strict boolean: only a literal `true`
  proceeds; `false`, any truthy non-boolean, a returned Promise (async misuse),
  or a thrown predicate all deny with a generic 403 (fail closed). The kit ships
  only the mechanism; services own the policy.
- IP allowlist matching is documented as an EXACT `req.ip` string compare (no
  CIDR/ranges) that relies on a correct Express `trust proxy`; an invalid
  `expiresAt` Date is treated as expired; and in `optional` mode only a
  genuinely absent credential passes through (a present-but-malformed credential
  is still a 401). Audit hooks (`onFailure`, `onDenied`) may be async — their
  rejections are caught and logged and must not send responses.

## 0.1.0

Initial release. Phase 1 scope: the security MACHINERY only — consuming
services inject all policy.

### Added

- **Helmet preset** — `createHelmetMiddleware(config?)`. Builds a hardened
  helmet middleware from a strict CSP base (`default-src 'self'`;
  `object-src`/`frame-src` `'none'`; `img-src 'self' data: https:`;
  `base-uri`/`form-action 'self'`; HSTS 1y with `includeSubDomains` + `preload`).
  Callers merge EXTRA CSP sources per directive (`scriptSrc`, `styleSrc`,
  `fontSrc`, `imgSrc`, `connectSrc`, `frameSrc`, `workerSrc`), optionally allow
  `'unsafe-inline'` styles, tune HSTS max-age, and deep-merge raw `HelmetOptions`
  overrides that win last.
- **Rate limiter** — `createRateLimiter(config | config[])`. Fixed- and
  sliding-window (weighted current+previous) algorithms; single or dual-tier
  (array) limiting for the recommended per-IP-flood + per-principal fair-share
  pattern; role-aware `max` as a function; per-principal overrides via
  `securityContext.rateLimitOverride`; `skip`/`onLimit` hooks; `RateLimit-*` and
  `Retry-After` headers; a `{ error: { code: 'RATE_LIMITED' } }` 429 body; and
  fail-OPEN behavior on store errors.
- **Key-generation strategy toolkit** — `ipKey`, `verifiedIdentityKey`
  (default), and the `decodedJwtKey()` factory (decode-without-verify pre-auth
  keying that never throws and falls back to per-IP).
- **Stores** — built-in `MemoryRateLimitStore` (bounded, self-evicting,
  `unref`'d timer) as the default, plus an optional
  `@andrewpopov/express-security-kit/redis-store` subpath (`RedisRateLimitStore`,
  ioredis as an OPTIONAL peer) so the core stays dependency-free.
- **Shared `SecurityContext`** type + Express `Request.securityContext`
  augmentation, read by the rate limiter's key generators and override resolver.
