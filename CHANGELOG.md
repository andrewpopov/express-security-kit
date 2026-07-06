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
