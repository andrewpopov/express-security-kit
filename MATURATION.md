# Maturation Spec — v0.5.0 → v1.0

A concrete roadmap for hardening `@andrewpopov/express-security-kit` from its
current v0.5.0 state to a stable, GA-quality v1.0. This is about maturing the
**package**; per-service adoption work (smarthome, stoki) is tracked separately
in BWK-93 and appears here only as a v1.0 gate.

## Where we are (v0.5.0)

**Solid:**

- All five pillars shipped across 5 tagged releases (v0.1.0–v0.5.0), each
  Codex-reviewed, with a CI release-guard that blocks tag/`package.json`/
  CHANGELOG drift.
- 172 passing tests across 16 files, covering every module: fail-open/
  fail-closed paths, timing-safe compares, hook rejection swallowing,
  `AuditBuffer` re-queue/drop-oldest/close-drain, nonce fail-closed-at-capacity.
- Zero runtime dependencies in the core; `ioredis` isolated behind the
  `./redis-store` subpath with a locally-declared `RedisLikeClient` structural
  type so even the type graph stays clean.
- `verify:pack` CI step catches packaging regressions (d.ts shipping, CJS
  `require`, ESM named-export resolution via cjs-module-lexer).
- Fail-direction is deliberate and documented per pillar: rate-limit fails
  OPEN, api-key/signing fail CLOSED, audit is fire-and-forget.
- One real production adopter: **cairn** (helmet + rate-limit + api-key, live).

**Missing for v1.0:** real-Redis and full-stack integration tests, adversarial
(property/fuzz) tests for the crypto-adjacent code, a security-model doc,
Node-matrix CI, a distribution decision, and 2–3 production adoptions covering
the signing and audit pillars (currently exercised only by unit tests).

## v1.0 criteria (GA gates)

v1.0 means "the API is frozen and every pillar has survived production." Gates,
all required:

1. **All 5 pillars adopted in prod** by ≥2 services each for helmet/rate-limit/
   api-key (cairn ✅ + one more), and ≥1 real service for signing (stoki) and
   audit (smarthome). No pillar GAs on unit tests alone.
2. **RedisRateLimitStore battle-tested**: run multi-instance in at least one
   deployment for ≥2 weeks with no correctness incident, plus the real-Redis
   integration suite below.
3. **API frozen**: one pre-1.0 pass to resolve known warts (below), then no
   breaking changes without a major bump. Publish the SemVer policy in the
   README.
4. **Docs complete**: security-model doc, per-module README accuracy pass,
   migration guide from hand-rolled middleware.
5. **CI matrix green** on Node 20 + 22, and the distribution decision (npm vs
   `github:` tag) made and documented.

Known API warts to resolve **before** freezing (each is cheap now, breaking
later):

- `RateLimitStore.reset(key)` takes no `windowMs`, forcing
  `RedisRateLimitStore.reset` into the `RESET_WINDOW_GUESSES` hack (1s/1m/15m/
  1h/1d — custom windows are silently not cleared). Change the signature to
  `reset(key, windowMs?)`.
- `RedisRateLimitStore` bucket keys omit `windowMs`
  (`<prefix>:<key>:<windowIndex>`), while `MemoryRateLimitStore` namespaces by
  `${key}::${windowMs}`. Concurrent same-key/different-window limiters can't
  practically collide (indexes only coincide at t=0), but the asymmetry is a
  trap for anyone reasoning from one store to the other — include `windowMs` in
  the Redis key for parity. Breaking for live Redis data → do it pre-1.0.
- Decide whether `defaultKeyGenerator` (alias of `verifiedIdentityKey`) stays;
  aliases are freeze liabilities.

## Testing gaps

Current suite is thorough unit coverage but everything runs against fakes and
hand-mounted middlewares. Concrete additions, in priority order:

1. **Real Redis integration test** for `RedisRateLimitStore`. The existing
   `redis-store.test.ts` uses a hand-written `FakeRedis` — real INCR/PEXPIRE
   semantics, TTL expiry across window boundaries, and ioredis error shapes are
   untested. Add a CI job with `services: redis` (GitHub Actions) running the
   same assertions plus: sliding estimate across a real window rollover,
   `reset` for the guessed windows, and behavior when Redis returns errors
   mid-`hit` (the limiter must fail open).
2. **End-to-end stack test**: one supertest-driven Express app composing the
   full documented ordering — helmet → Tier-1 rate-limit → `createApiKeyAuth`
   → `createRequestSigningVerifier` → Tier-2 rate-limit → `requireScope` →
   route — with all three audit hook adapters wired into one `AuditBuffer`.
   Assert: headers set, a signed+keyed request passes, each failure mode short-
   circuits at the right layer with the right status, and exactly the expected
   audit events land in a capture sink. This is the test that catches inter-
   module contract drift (e.g. `securityContext.hmacSecret` population → secret
   resolver) that no per-module test can.
3. **Property/fuzz tests** (fast-check as a devDependency):
   - `buildCanonicalString`: no two distinct `(method, url, timestampMs, nonce,
     body)` tuples may produce the same canonical string (LF-injection through
     `url`/`nonce` is the obvious attack; the nonce format regex excludes `\n`
     but the canonical builder itself should be proven, since custom
     `nonceFormat` regexes can widen it).
   - `timingSafeEqualHex`: never throws for arbitrary string pairs; equals iff
     byte-identical; length mismatch → false.
   - `decodedJwtKey`: never throws for arbitrary header garbage (currently
     asserted with examples; make it a property).
4. **Concurrency/load tests**: parallel `hit()` bursts against
   `MemoryRateLimitStore` (drop-oldest eviction under churn) and
   `MemoryNonceStore` (N concurrent `consume` of the SAME nonce must yield
   exactly one `'ok'`); `AuditBuffer` with a slow sink under sustained
   `record()` load must respect `maxQueueSize` and single-in-flight flushes.
   These can be plain vitest tests with `Promise.all` fan-out — no external
   tooling needed.

## Hardening

Items already flagged in code/CHANGELOG that deserve guardrails or louder docs:

- **AuditBuffer at-least-once**: failed batches re-queue at the FRONT and can be
  re-sent, so sinks may see duplicates. This is correct (at-least-once beats
  at-most-once for audit) but currently implicit. Document it as a contract and
  add an optional per-event `id` (uuid or monotonic counter) in
  `buildAuditEvent` so durable sinks can dedupe.
- **Shared default memory store**: limiters created without an explicit `store`
  share one process-wide `MemoryRateLimitStore`. Buckets are namespaced by
  `${key}::${windowMs}` so tiers don't collide, but they DO share the
  `maxTrackedKeys` eviction budget — a flood on Tier 1 can evict Tier 2's
  buckets. Document; consider per-limiter default stores or a per-limiter key
  namespace.
- **IP allowlist + trust proxy**: both `ipKey` and the api-key IP allowlist are
  only as good as `req.ip`, which behind cloudflared/reverse proxies collapses
  to one address without correct `trust proxy`. The JSDoc warns; the runtime
  doesn't. Add a cheap one-time startup warning when an `ipAllowlist` (or
  `ipKey`) is configured and `app.get('trust proxy')` is unset — detectable in
  middleware from `req.app`.
- **`decodedJwtKey` forge-victim tradeoff**: a forged token can claim a
  victim's `sub` and burn their bucket. The JSDoc says "only behind a Tier-1
  per-IP flood limiter" but nothing enforces or surfaces it. At minimum promote
  this to the README's key-strategy table; optionally emit a one-time warning
  when `decodedJwtKey` is used in a single-config (non-array) limiter.
- **`defaultBodySource` JSON re-serialization fallback**: when `rawBody` is
  absent, signing verification hashes `JSON.stringify(req.body)`, which can
  silently differ from the client's bytes. Consider a `requireRawBody: true`
  config (fail closed with reason `'no_raw_body'`) for services that want the
  footgun removed.
- **Nonce store TTL vs skew**: nonce TTL is `maxSkewMs`, correct only because
  skew is checked first; a comment exists but an invariant test pinning
  "timestamp check always precedes nonce consume" would keep a refactor honest.

## Docs & DX

- **README accuracy pass**: the intro still says "Phase 1 ships two modules —
  ... API-key auth, HMAC request signing, and audit logging are LATER phases
  and are intentionally NOT in this package yet" while Modules 3–5 are
  documented 400 lines later; the install pin says `#v0.1.0`; and the "Fail
  direction differs by layer" blockquote appears twice back-to-back. Fix all
  three; add a `verifyApiKey` mention to the intro.
- **SECURITY.md / security-model doc**: threat model per pillar (what each
  defends against, what it explicitly does not — e.g. rate-limit is not DoS
  protection, IP allowlist is not CIDR-aware), the fail-open/fail-closed matrix
  as a table, the replay-protection window semantics, and the reporting policy
  for vulnerabilities.
- **Adoption recipes**: the README already has excellent per-service recipes
  (stoki/smarthome/cairn per module). Keep them and add one "full stack in 30
  lines" recipe matching the e2e test from the Testing section, so the test and
  the doc can never drift apart.
- **Migration guide**: a short `docs/MIGRATING.md` mapping hand-rolled patterns
  → kit equivalents (express-rate-limit → `createRateLimiter`, ad-hoc
  `x-api-key` checks → `createApiKeyAuth`/`verifyApiKey`, bespoke HMAC →
  `signRequest`/verifier), including the two integration gotchas: `rawBody`
  capture via `express.json({ verify })` and `trust proxy`.

## Release & CI

- **Node matrix**: CI pins Node 20 only. Add `strategy.matrix.node: [20, 22]`
  to the test job (engines already say `>=20`).
- **Distribution decision**: currently `github:andrewpopov/express-security-kit#vX.Y.Z`
  with no committed `dist/` verification beyond `verify:pack`. Decide before
  v1.0: publish to npm under `@andrewpopov` (provenance, `npm audit`
  visibility, no build-on-install questions) vs staying on github: tags
  (zero-infra, current fleet convention per BWK-84/85). Either is fine; the
  gate is writing the decision down and, if github:, adding a CI check that the
  tagged commit's `dist/` is fresh (`npm run build && git diff --exit-code dist`).
- **SemVer + advisory policy**: one README paragraph — pre-1.0 minor bumps may
  break; post-1.0 strict SemVer; security fixes are patched on the latest minor
  only; advisories via GitHub Security Advisories on this repo.

## Roadmap features (post-hardening, mostly post-1.0)

- **Redis store completeness**: pipeline the 3 round-trips in `hit()` into one
  `MULTI`/pipeline (or a Lua script) so INCR+PEXPIRE are atomic — today a crash
  between them leaks a never-expiring key — and fix `reset` per the API-wart
  item. A `RedisNonceStore` for the signing pillar is the natural companion
  (multi-instance signing currently requires the consumer to hand-roll one).
- **Prisma audit sink adapter**: smarthome and cairn both persist audit to
  Prisma; a `createPrismaAuditSink(delegate)` adapter (accepting a structural
  `{ createMany }` type, same trick as `RedisLikeClient`) would make the audit
  pillar drop-in. Ship as a subpath export to keep the core dependency-free.
- **Request-signing key rotation**: `SecretResolver` already permits per-key
  secrets; add first-class dual-secret verification (accept `current` or
  `previous` during a rotation window) so consumers can rotate HMAC secrets
  with zero downtime.
- **CSP nonce support**: `createHelmetMiddleware` currently offers
  `allowUnsafeInlineStyles`; add optional per-request nonce generation
  (`res.locals.cspNonce` + `'nonce-...'` in script/style-src) as the strict
  alternative. (Known consumer demand: bewks deferred exactly this in BWK-60.)
- **Optional OpenTelemetry hooks**: the hook surface (`onLimit`, `onFailure`,
  `onDenied`, `onAuthenticated`) is already the right seam — ship a tiny
  `otelHooks()` adapter emitting span events/counters, as a subpath export with
  `@opentelemetry/api` as an optional peer. Do not bake OTel into the core.

## Prioritized next actions

**P0 (before any more feature work):**

1. README accuracy pass: stale "Phase 1" intro, `#v0.1.0` install pin,
   duplicated fail-direction blockquote. (~30 min)
2. Add Node 20/22 matrix to `ci.yml`. (one-line)
3. Real-Redis CI job + integration tests for `RedisRateLimitStore`.

**P1 (the v1.0-shaping work):**

4. End-to-end composed-stack supertest suite with audit capture.
5. Pre-1.0 API-wart pass: `reset(key, windowMs?)`, Redis bucket-key
   `windowMs` parity, alias decision. One breaking minor (v0.6.0).
6. Property tests for `buildCanonicalString` / `timingSafeEqualHex` /
   `decodedJwtKey` (fast-check).
7. SECURITY.md with the threat model + fail-direction matrix + advisory policy.

**P2 (nice-to-have before GA, or fast-follow):**

8. Concurrency tests (same-nonce race, buffer under slow sink).
9. Trust-proxy startup warning; `requireRawBody` option; audit event `id`.
10. Pipeline/Lua for Redis `hit()`; `RedisNonceStore`; Prisma audit sink
    subpath.
11. Distribution decision (npm vs github:) + dist-freshness CI check if
    staying on tags.

Adoption itself (smarthome audit+scopedHmac, stoki signing) is the remaining
v1.0 gate and is tracked in BWK-93 — not re-planned here.
