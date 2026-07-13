# Changelog

## 1.3.2

- Upgrade the Vitest/Vite development toolchain to remove the known development
  dependency advisories.
- Add `npm run verify`, including runtime and development dependency audits, as
  the authoritative local release gate.

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

## 1.3.1

Fix — `normalizeIp` did NOT map the IPv6 loopback (`::1`) to `127.0.0.1`, while its
doc comment claimed to be "a superset of savoro's normalizeIp". savoro's version
does map it. Adopting v1.3.0 would therefore have silently started DENYING a key
allowlisted as `127.0.0.1` whenever the socket reported `::1` — a regression, in
the very function added to be a superset. Found because savoro's adoption refused
to delete its wrapper and reported the gap instead of papering over it.

`::1` and `0:0:0:0:0:0:0:1` now canonicalize to `127.0.0.1`.

## 1.3.0

Folds three consumer-hand-rolled improvements back into the shared package
(`shared-package-standards.md` Part 2, standard 1: a shared package must be a
superset of the best implementation across its consumers). All three were
verified present in an app and absent from the kit.

### BREAKING (within a minor bump — read this before upgrading)

**Infrastructure errors during api-key verification now return 503, not
401, by default.** When `lookup` or `hasher` throws (e.g. a DB outage), the
kit previously reported it as a generic 401 — indistinguishable from a
bad/revoked key. That is wrong: a DB outage would make monitoring blind (it
looks like normal auth-failure traffic) and cause clients to treat valid
keys as revoked and re-provision. `verifyApiKey`'s `reason: 'error'` outcome
now carries `status: 503` by default, and `createApiKeyAuth` responds 503
with `{ error: { code: 'SERVICE_UNAVAILABLE', message: 'Service
Unavailable' } }`.

This is exactly the workaround savoro (`packages/api/src/middleware/
integrationAuth.ts`, `mapApiKeyFailure`) and cairn (`packages/api/src/
middleware/auth.ts`, `apiKeyAuth`) each wrote their own response layer to
avoid — both are now redundant (though harmless to keep) once on this
version. Two new knobs let a consumer choose the exact behavior:

- `errorStatus?: number` — override the status (e.g. cairn's prior 500).
- `onError?: (req) => { status, body } | void` — override the full response;
  a throw/rejection falls back to `errorStatus`. Never turns the failure
  into an allow — `verifyApiKey` still fails closed in every case.

If you read `outcome.status` directly (bypassing `createApiKeyAuth`) and
compared it to a `401 | 403` literal union, note the type is now `number`.

### Fixed

- **IP allowlist now normalizes IPv4-mapped IPv6 addresses.** A key
  allowlisted as `203.0.113.7` was spuriously denied (403) when the socket
  reported `req.ip` as `::ffff:203.0.113.7` — common behind some
  proxies/load balancers. Both sides of the allowlist comparison are now run
  through a new `normalizeIp` (strips the `::ffff:` prefix case-
  insensitively, lowercases, trims) before comparing. A superset of
  savoro's own `normalizeIp` (savoro only strips the lowercase-exact
  prefix). Still an exact match — no CIDR/range support was added, matching
  savoro's scope. `normalizeIp` is now also exported for direct use.

### Added

- **API-key issuance module** (`generateApiKey`, `parseApiKey`,
  `maskApiKey`, `rotateApiKey`, `createThrottledTouchLastUsed`, plus an
  `ApiKeyStore` port type). The kit previously covered verification only;
  mint/parse/mask/rotate/touch was hand-rolled separately in bewks
  (`src/lib/auth/apiKeys.ts`), cairn (`packages/api/src/services/
  apiKey.service.ts`), savoro (`packages/api/src/routes/admin/
  api-keys.ts`), and smarthome (`packages/api/src/services/
  api-key.service.ts`). The new module is a superset:
  - **Key format** — `<prefix><keyId>.<secret>`, taken from savoro (the most
    capable of the four): a public, unhashed `keyId` for indexed lookup plus
    a secret that alone gets hashed, so `ApiKeyStore.findByKeyId` never
    needs a table scan.
  - **Display mask** — `maskApiKey` folds in smarthome's `prefix...last4`
    mask, combined with savoro's public-`keyId` visibility, without ever
    exposing the secret.
  - **Transactional rotate** — `rotateApiKey` takes an `ApiKeyStore` with an
    optional `transaction` method, folding in bewks's transactional
    rotate (insert-then-revoke inside one transaction) when the store
    supports it; without it, falls back to insert-before-revoke so there is
    never a window where neither key works.
  - **Throttled `lastUsedAt`** — `createThrottledTouchLastUsed` wraps
    `store.touchLastUsed` so a hot verification path writes at most once per
    key per configurable window, instead of on every request (all four apps
    currently write per-request; bewks additionally swallows write failures
    via `.catch(() => {})` — the kit's version routes failures to an
    `onError` callback instead of silently dropping them).
  - Pure functions plus an `ApiKeyStore` port — **no ORM dependency**; each
    app keeps its own (Prisma, raw SQL, ...).
  - Reuses the kit's existing hasher seam (`sha256Hasher` /
    `scopedHmacHasher`) — no second hashing scheme.

  **Left out as app-policy** (not folded in — each is specific to one app's
  authorization model, not the key mechanics the kit owns): cairn's
  project-scope resolution (`projectScopes` -> project ids, bot-user
  minting), savoro's per-key `allowedActions`/`allowedListIds` CSV
  authorization and env-key fallback, and bewks's role-based
  "who can rotate whose key" check. These stay in each app.

## 1.2.2

Fix — expose `./package.json` in the `exports` map. Without it,
`require('@andrewpopov/express-security-kit/package.json')` threw
`ERR_PACKAGE_PATH_NOT_EXPORTED` — which broke the standards' own documented way of
verifying an INSTALLED version, the guard against the `github:` re-resolve trap.

No runtime change.

## 1.2.1

Purely additive: the CORS + webhook module surfaces added in v1.2.0 are now
**also** available from the root (`.`) export, for consistency with the other
Express middleware (`createHelmetMiddleware`, `createRateLimiter`,
`createApiKeyAuth`, `requireScope`, `createRequestSigningVerifier`, ...) that
was already root-exported. The `./cors`, `./express/cors`, `./webhook`, and
`./express/webhook` subpaths are unchanged — nothing moves, nothing is
removed.

- Root now also exports: `verifyWebhookSignature`, `createWebhookVerifier`,
  `resolveCorsPolicy`, `normalizeOrigin`, and their public types
  (`WebhookVerifyConfig`, `HmacSha256Config`, `Ed25519Config`,
  `Ed25519TimestampConfig`, `ReplayConfig`, `WebhookVerifyReason`,
  `WebhookVerifyOutcome`, `WebhookHeaders`, `HeaderReader`,
  `PublicKeyResolver`, `ReplayIdFromVerifiedBody`, `WebhookVerifierConfig`,
  `WebhookVerifierExpressConfig`, `WebhookVerifierLogger`,
  `CorsPolicyConfig`, `CorsPolicy`, `CorsRejectHook`). The webhook module's
  `SecretResolver` type collides by name with the root's existing (request-
  signing) `SecretResolver` — it is re-exported as `WebhookSecretResolver`
  instead; the two have different signatures and were never the same type.
- `corsOptions` (the `cors`-package adapter in `./express/cors`) deliberately
  **stays subpath-only** and is NOT added to root: its return type is
  `CorsOptions` from the `cors` package, and re-exporting it from root would
  force `@types/cors` to resolve for every root consumer's TypeScript
  compile, even one that never uses CORS. Verified via `verify:pack`: a
  consumer that installs only `express` (root's own peer) — no `cors`/
  `@types/cors` — fails `tsc` with `TS2307: Cannot find module 'cors'` when
  `corsOptions` is exported from root, and passes once it is left off.
  `resolveCorsPolicy`/`normalizeOrigin` have no such dependency and are safe
  on root.

## 1.2.0

Three new **framework-agnostic security modules** (additive; the v1.1.0 root
`.`, `./core`, and `./redis-store` surfaces are unchanged). Each lives in
`core/` with a thin `express/` adapter and its own subpath export; `cors` and
`ioredis` stay optional peers, out of the core module graph.

- **Durable nonce store** — `RedisNonceStore` (new `./nonce-redis` subpath).
  Multi-instance replay protection via Redis `SET NX PX` (atomic
  set-if-absent-with-TTL), implementing the existing `NonceStore` contract.
  Strict reply handling (`OK`→ok, `null`→replay, anything else throws
  `store_unavailable`); scope+nonce both SHA-256-hashed into the key. Closes
  the "only `MemoryNonceStore`" gap.
- **CORS fail-closed policy** — `resolveCorsPolicy` (`./cors`) + `corsOptions()`
  (`./express/cors`). Core does origin-resolution only: prod + empty allowlist
  throws at construction; exact-match only — **never reflects an arbitrary
  origin** (no `*`, no regex); opaque-origin schemes (`data:`/`file:`/
  `javascript:`) are rejected rather than silently collapsed to `"null"`; the
  literal `"null"` origin remains an explicit opt-in. The express wrapper emits
  the canonical matched origin (never `callback(null, true)`, which would
  reflect the raw Origin) and carries the full header/method defaults.
- **Inbound webhook signature verifier** — `verifyWebhookSignature` (`./webhook`)
  + `createWebhookVerifier()` (`./express/webhook`). Pluggable **HMAC-SHA256**
  (GitHub `x-hub-signature-256` style) and **Ed25519** (Discord style),
  discriminated on `scheme`. Replay identity derives ONLY from authenticated
  material (the verified signature, or a verified-body extractor) — never a
  mutable header; replay scope is a static string. HMAC has no timestamp check
  (GitHub signs only the body); Ed25519 enforces skew because the timestamp is
  part of the signed message, and fails closed on non-finite skew/clock config.
  Constant-time compare with a length pre-check; strict hex/header validation;
  a config/crypto exception is never mislabeled as a forged signature. The
  express adapter maps failures to generic 401/503 responses that never leak
  the reason.

Also: the `check:core-agnostic` guard now additionally forbids `cors`/`ioredis`
imports and any relative import escaping `src/core/`.

## 1.1.0

Framework-agnostic **core carve** (Phase 1 of the core/adapter split). Backward
compatible — the root (`.`) export is unchanged in runtime exports and public
type shapes, so cairn / savoro / smarthome upgrade with **zero code change**.

- **New `./core` subpath export** exposing the framework-agnostic surface
  (`verifyApiKey`, hashers, key generators, rate-limit stores, nonce store,
  audit buffer/hooks, signing primitives) with no `express`/`fastify` in its
  module graph. Enables a future Fastify adapter to reuse the security
  machinery. Request-coupled core types are generic over a new `SecurityRequest`
  seam: `<Req extends SecurityRequest = SecurityRequest>`.
- **Internal restructure** into `src/core/` (agnostic) + `src/express/`
  (adapter). The Express `Request` augmentation (`req.securityContext`,
  `req.rawBody`) moved to an express-only module, loaded via a side-effect
  import from the root so root consumers keep it. The signing verifier and rate
  limiter are unchanged (kept whole in the Express adapter).
- **New guards:** `check:core-agnostic` (fails on any `express`/`fastify` import
  — incl. `import type`, dynamic `import()`, and relative escapes — under
  `src/core/`); `verify:pack` now type-checks a node16-strict consumer fixture
  asserting the augmentation and the `Request`-pinned public signatures.

Notes for consumers:
- Root `ApiKeyAuthConfig` and `DecodedJwtKeyOptions` are now `type` aliases
  (previously `interface`). Only observable if you declaration-merge onto those
  names, which no known consumer does.
- The `./core` subpath (like `./redis-store`) requires TypeScript
  `moduleResolution` of `node16`/`nodenext`/`bundler`; `node10` cannot resolve
  subpath `exports`.

## 1.0.0

First stable release. **No API changes from 0.8.0** — this promotes the library to
a stable 1.x now that three services depend on it in production:

- **cairn** — helmet + api-key
- **smarthome** — helmet + api-key + audit + rate-limit
- **stoki** — helmet + request-signing + api-key + rate-limit

The public API — helmet preset (`createHelmetMiddleware`), rate limiter
(`createRateLimiter` with `skipSuccessful` / `buildResponseBody` /
`overrideResolver` / memory + Redis stores), api-key (`verifyApiKey`), request
signing (`createRequestSigningVerifier`, `signRequest`, `MemoryNonceStore`), and
audit (`AuditBuffer`) — is considered stable. Future breaking changes will bump
the major version.

## 0.8.0

### Added (rate-limit — skipSuccessful / refund)

- **`RateLimiterConfig.skipSuccessful?: boolean`** (default false, opt-in,
  non-breaking) — when true, a request that ends with a status `< 400` is
  REFUNDED (its counted hit is decremented) so only failed requests count toward
  the limit, mirroring express-rate-limit's `skipSuccessfulRequests` (e.g. an
  auth limiter where only failed logins should count). Default behavior is
  unchanged when the flag is unset.
- **`RateLimitStore.decrement(key, windowMs?, now?)`** added to the store
  interface. `MemoryRateLimitStore` and `RedisRateLimitStore` both implement it,
  flooring at 0 and targeting the EXACT bucket the matching `hit` incremented
  (the `windowMs`/`now` passed are the same values used for that `hit`). The
  Redis path uses a conditional-DECR Lua script (never a phantom key, never
  negative); an eval-less test double falls back to non-atomic GET-then-DECR.

### Fixed (skipSuccessful refund semantics — Codex review)

- The refund fires ONLY on response `finish`. A `close` without `finish` is an
  aborted request (status not final — often still the default 200) and is NOT
  refunded; `close` only cleans up listeners.
- `MemoryRateLimitStore.decrement` targets the hit-time window: if the bucket
  rolled between `hit` and refund, the original hit's count moved into
  `previous`, so it decrements `previous` (or no-ops if the window fully
  expired) rather than an unrelated current-window request.
- The refund guard is per-LIMITER (a unique symbol per built limiter), so
  tiered limiters each refund their own counted hit.
- The two fail-open paths and the refund catch route through `safeWarn`, so a
  throwing custom `logger` can't turn a store blip into a 500.

## 0.7.0

### Changed (rate-limit store — correctness hardening)

- **`RateLimitStore.reset(key, windowMs?)`** — `reset` now accepts an optional
  `windowMs`. `MemoryRateLimitStore.reset(key, windowMs)` deletes only that
  exact window bucket; `RedisRateLimitStore.reset(key, windowMs)` deletes the
  EXACT current+previous buckets for that window (no guessing). Omitting
  `windowMs` keeps prior behavior (`MemoryRateLimitStore` clears every window
  for the key; `RedisRateLimitStore` falls back to a fixed set of common
  window-size guesses — see `RESET_WINDOW_GUESSES` in the README).
- **`RedisRateLimitStore` bucket keys now include `windowMs`**:
  `<keyPrefix>:<key>:<windowMs>:<windowIndex>` (previously
  `<keyPrefix>:<key>:<windowIndex>`), matching `MemoryRateLimitStore`'s
  per-window-length namespacing so two limiters sharing a store/key with
  different window lengths never collide. **Breaking for live Redis DATA
  only** — old-format buckets are simply orphaned and TTL-expire on their
  own; no action needed.
- **Atomic INCR+PEXPIRE via an optional `eval`** — fixes a never-expiring-key
  leak. Previously `hit()` ran INCR then a SEPARATE PEXPIRE then GET; a crash
  between the two left a key with NO TTL, leaking forever. `RedisLikeClient`
  gains an OPTIONAL `eval?(script, numKeys, ...args)`. When present (real
  ioredis always implements it), `hit()` runs ONE atomic Lua script: INCR,
  then re-arm the TTL whenever `PTTL < 0` (covers a fresh key AND a
  previously-leaked key — self-healing), then GET the previous bucket — one
  round trip, atomic, so INCR+PEXPIRE can never be torn. The eval result is
  STRICTLY parsed (array shape, finite non-negative integers); a malformed
  result THROWS rather than silently coercing, which `createRateLimiter`
  catches and fails OPEN on (the desired behavior for a store anomaly). When
  the client has no `eval`, `hit()` falls back to the original 3-call path —
  this fallback is explicitly NON-ATOMIC and does NOT fix the leak; it exists
  only for eval-less test doubles, since real ioredis always has `eval`.

### Added (rate-limit — skipSuccessful / refund)

- **`RateLimiterConfig.skipSuccessful?: boolean`** (default false, opt-in,
  non-breaking) — when true, a request that ends with a status `< 400` is
  REFUNDED (its counted hit is decremented) so only failed requests count
  toward the limit, mirroring express-rate-limit's `skipSuccessfulRequests`
  (e.g. an auth limiter where only failed logins should count). The refund
  fires once on response `finish`/`close` (both hooked so the listeners can't
  leak if the socket dies), is guarded by a per-response symbol so it runs AT
  MOST once, only refunds a `< 400` response, and is never applied to a rejected
  (429) request. It never throws; a refund error is logged via the configured
  logger. Default behavior (option unset) is unchanged.
- **`RateLimitStore.decrement(key, windowMs?, now?)`** — new store method used
  by the refund. `MemoryRateLimitStore` decrements the current-window counter
  (floored at 0; no-op if the key/window is gone). `RedisRateLimitStore` does a
  conditional-DECR of the exact window bucket via a Lua script (or a non-atomic
  GET-then-DECR fallback for eval-less clients) that never creates a phantom key
  or drives a counter negative. `windowMs`/`now` are optional so `decrement(key)`
  remains valid, but `createRateLimiter` passes the same `windowMs`/`now` it used
  for the corresponding `hit` so windowed stores target the exact bucket.
  `RedisLikeClient` gains a `decr` method.

### Added (signing hardening)

- **CR/LF-injection guard in `buildCanonicalString`** — `method`, `url`, and
  `nonce` are now rejected (`Invalid canonical field: <field> must not
  contain CR/LF`) if they contain a raw `\n` or `\r`. Without this, a
  CR/LF-carrying `url`/`nonce` could let two distinct request tuples
  canonicalize to the same LF-joined string (delimiter ambiguity), risking
  signature reuse across requests. Valid HTTP requests never carry a raw
  CR/LF in these fields, so this only rejects malformed/hostile input — the
  wire format for valid inputs is byte-identical (stoki compat preserved).
- **`requireRawBody` option on `createRequestSigningVerifier`** — when `true`,
  a body-bearing request (never GET/HEAD) that arrives without `req.rawBody`
  FAILS CLOSED (`no_raw_body`) instead of silently hashing
  `JSON.stringify(req.body)` (which can diverge from the client's exact
  signed bytes). Default `false` (unchanged behavior). Only governs the
  DEFAULT body extractor — a custom `bodySource` participates as provided.

### Added (audit)

- **`AuditEvent.id`** (optional) — `buildAuditEvent` now sets `id` by default
  via `crypto.randomUUID()` (configurable via a new `id?: () => string`
  option on `BuildAuditEventOptions` / `AuditHookOptions`, threaded through
  `auditFailureHook` / `auditRateLimitHook` / `auditDeniedHook`). Intended for
  DEDUPE by a durable sink, since `AuditBuffer` delivery is at-least-once —
  make `sink.write` idempotent (e.g. upsert on `id`) if you rely on exactly-
  once storage. Additive; existing exact-`toEqual` assertions on a built
  event should inject a deterministic `id` (or switch to
  `expect.objectContaining`).

### Added (testing)

- Property/fuzz tests (new DEV dependency: `fast-check`) covering
  `buildCanonicalString` (no delimiter ambiguity for CR/LF-free fields; any
  CR/LF in `method`/`url`/`nonce` throws), `timingSafeEqualHex` (never
  throws; true iff byte-identical; false on length mismatch), and
  `decodedJwtKey` (never throws on arbitrary header garbage).
- Concurrency tests for `MemoryRateLimitStore` (N parallel hits, no lost
  updates; drop-oldest eviction stays bounded under a key flood),
  `MemoryNonceStore` (N concurrent consumes of the same nonce yield exactly
  one `'ok'`), and `AuditBuffer` (sustained `record()` against a slow sink
  respects `maxQueueSize` and never runs two flushes concurrently).
- A real-Redis integration test suite for `RedisRateLimitStore`
  (`redis-store.integration.test.ts`), skipped locally/in the normal `test`
  job unless `ESK_REDIS_URL` is set; a new non-required `redis-integration`
  CI job runs it against a `services: redis` container.

### Docs

- README: removed the stale "Phase 1" intro (API-key/HMAC/audit are
  documented, not future work), fixed the install pin (`#v0.1.0` →
  `#v0.7.0`), removed a duplicated "Fail direction differs by layer"
  blockquote, added a `verifyApiKey` mention to the module list, and
  updated the Redis store section for the `windowMs`-scoped bucket keys and
  atomic-`eval` hit path.
- Added `SECURITY.md` (per-pillar threat model, fail-open/fail-closed
  matrix, replay-window semantics, vulnerability reporting) and
  `docs/MIGRATING.md` (hand-rolled → kit mapping, `rawBody`/`trust proxy`
  gotchas).

### CI

- `test` job gains a dist-freshness check (`npm run build && git diff
  --exit-code dist`) so a stale committed `dist/` fails CI.
- New non-required `compat` job (Node 22) + `ci-success` aggregate gate
  (mirrors the deploy-kit CI pattern) so `test` stays a stable required
  status-check name.
- New non-required `redis-integration` job (Redis service container) runs
  the real-Redis integration suite.

## 0.6.0

### Added

- **Custom rate-limit 429 response body** (non-breaking). `createRateLimiter`
  config gains two options so a service can match its own API error envelope:
  - `message?: string` — overrides ONLY the message text inside the default
    envelope (`{ error: { code: 'RATE_LIMITED', message, retryAfter } }`); the
    shape and code are unchanged.
  - `buildResponseBody?: (info: RateLimitRejection) => unknown` — returns the
    ENTIRE JSON body, replacing the default envelope (e.g. smarthome's
    `{ error: '<string>' }`). `RateLimitRejection` (`{ limit, remaining, resetAt,
    retryAfterSeconds, key, req }`) is exported. A throwing formatter can never
    break the response — it falls back to the default body (honoring `message`)
    and logs via the configured logger; status stays 429 and headers are still
    emitted.
  - A custom body is validated before it is sent: a nullish return, a thenable
    (async formatters are rejected — the body is resolved synchronously), or a
    non-JSON-serializable value (circular / `BigInt`, which would make
    `res.json` throw into Express's error path) all fall back to the default
    body + log, so a custom formatter can never break the 429. Logging itself is
    guarded so a throwing logger cannot suppress the fallback body.
  - Precedence: `buildResponseBody` > `message` > default. When neither is set
    the 429 body is **byte-unchanged**, so existing adopters (e.g. cairn) are
    unaffected.

## 0.5.0

### Added

- **`verifyApiKey(config, req)`** — a verify-ONLY primitive that runs the full
  API-key verification core (extract → prefix → static-key → hash+lookup → hash
  re-compare → expiry → IP allowlist → build context) and returns a discriminated
  `ApiKeyVerifyOutcome` INSTEAD of sending HTTP or mutating the request. This
  lets a service with a unified/multi-method auth flow (try `x-api-key`, else
  JWT) reuse the kit's verification without adopting the fail-closed middleware.
  The outcome carries `present` (false only for a genuinely ABSENT credential,
  so callers can distinguish "fall through to another method" from "reject") and
  `status` (403 for `ip_denied`, else 401); on success it also returns the
  matched `record` (null for a static key). It NEVER throws (unexpected error →
  `{ ok: false, reason: 'error', present: true, status: 401 }`), does not call
  `onFailure`, and does not touch `req.securityContext`/`res` — but it DOES run
  `onAuthenticated`.
- `createApiKeyAuth` is now a thin middleware wrapper around `verifyApiKey`
  (behavior-preserving refactor — all existing tests pass unchanged).
- **`meta` passthrough** — `ApiKeyRecord` and `SecurityContext` gained an
  optional `meta?: Record<string, unknown>`. A service's `lookup` can attach
  e.g. `{ meta: { orgId } }` and read it back from `outcome.context.meta` /
  `outcome.record.meta`; the default context builder copies it across.

## 0.4.0

Phase 4 (final pillar) — buffered audit. Completes the kit: helmet, rate
limiting, API-key auth, request signing, and now audit.

### Added

- **`AuditBuffer`** — non-blocking, batched audit queue. `record(event)` never
  throws and never blocks the request path; it auto-flushes at `maxBufferSize`
  (default 100), on a `.unref()`'d timer (`flushIntervalMs`, default 5000), and
  hard-caps the queue at `maxQueueSize` (default 10000) by dropping the OLDEST
  events (counted via `onDropped`) so audit can never OOM. Flushes are
  single-in-flight and coalesced (no double-send). On a sink error the failed
  batch is re-queued at the FRONT for retry (`onFlushError`) — bounded by the
  hard cap so a persistently failing sink can't grow unbounded, and the flush
  loop stops re-spinning on failure. `close()` stops the timer and drains
  remaining events with a bounded retry (`closeMaxRetries`, default 3, short
  delay between attempts) so a transient sink failure at shutdown doesn't lose
  events; `stop()`/`dispose()` clear the timer.
  - Hardening: `record()`'s size-triggered flush is deferred to a microtask so a
    synchronous sink never runs inside the request's call stack; every internal
    log call is routed through a guarded `safeWarn` so a throwing logger can't
    make `flush()`/`close()` reject or skip `onDropped`; the sink receives a COPY
    of the batch (a mutating sink can't corrupt the re-queue); non-positive
    `maxBufferSize`/`maxQueueSize` are rejected at construction; the hook
    adapters are each independently never-throw; and `ConsoleAuditSink` guards
    every event independently (a single un-serializable event emits a fallback
    line instead of failing — and re-emitting — the whole batch).
- **`AuditSink` interface** (injected persistence) + **`ConsoleAuditSink`** — a
  JSON-lines dev sink; production injects a durable sink (Prisma / file / HTTP).
- **`buildAuditEvent(req, input, options?)`** — pure, never-throws normalizer
  that pulls principalType/principalId/keyId from `req.securityContext` and
  ip/method/path from the request, with an injectable clock.
- **Hook adapters** — `auditFailureHook` (api-key / signing `onFailure`),
  `auditRateLimitHook` (rate limiter `onLimit`), and `auditDeniedHook`
  (`requireScope.onDenied`) so one shared `AuditBuffer` wires into every pillar's
  audit hook in one line.

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
