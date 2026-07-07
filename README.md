# @andrewpopov/express-security-kit

A dependency-light Express security library. It owns the **machinery**;
consuming services inject all **policy**. It ships five modules: a hardened
**helmet preset**, a **rate limiter**, **API-key auth** (`createApiKeyAuth` /
`verifyApiKey`), **HMAC request signing + replay protection**, and **buffered
audit logging** — plus a shared `SecurityContext` type.

The core has **zero runtime dependencies**. `express` and `helmet` are peer
dependencies you already have; `ioredis` is an *optional* peer needed only if
you use the Redis store subpath.

## Install

This package is distributed via GitHub tags (not npm):

```bash
npm install github:andrewpopov/express-security-kit#v0.7.0
```

Peers (you almost certainly already have these):

```bash
npm install express helmet
# only if you use the Redis store:
npm install ioredis
```

## Middleware ordering

The full stack, with audit wired into each pillar's hook via ONE shared
`AuditBuffer`:

```
helmet
  → rate-limit (Tier 1: per-IP flood)      (+ onLimit    → auditRateLimitHook)
  → api-key auth                            (+ onFailure  → auditFailureHook)
  → signing verifier                        (+ onFailure  → auditFailureHook)
  → rate-limit (Tier 2: per-principal)      (+ onLimit    → auditRateLimitHook)
  → requireScope                            (+ onDenied   → auditDeniedHook)
  → routes
```

Security headers first, then a coarse flood guard *before* you spend CPU on auth,
then the API-key verifier (which populates `req.securityContext`, including a
per-key `hmacSecret`), then the signing verifier (which reads that secret), then
identity-aware fair-share limiting and scope guards, then your routes. Each
pillar's audit hook records to the shared buffer; the buffer batches to your
sink off the request path.

> **Fail direction differs by layer.** The rate limiter **fails open** (a store
> outage must not take the service down); the API-key verifier and the **signing
> verifier fail closed** (any error — including an unavailable nonce store — →
> generic 401, request denied). Audit is **fire-and-forget**: `record()` never
> throws or blocks, and a broken sink can never break the request. All
> intentional — see `SECURITY.md` for the full fail-open/fail-closed matrix.

## Module 1 — Helmet preset

`createHelmetMiddleware(config?)` returns a configured `helmet()` handler. It
starts from a **strict CSP base** and only widens where you pass extra sources:

| Directive | Base value |
|---|---|
| `default-src` | `'self'` |
| `script-src` | `'self'` |
| `style-src` | `'self'` (`+ 'unsafe-inline'` if `allowUnsafeInlineStyles`) |
| `connect-src` | `'self'` |
| `font-src` | `'self'` |
| `img-src` | `'self' data: https:` |
| `object-src` | `'none'` |
| `frame-src` | `'none'` (unless you extend it) |
| `base-uri` | `'self'` |
| `form-action` | `'self'` |
| HSTS | 1 year, `includeSubDomains`, `preload` |

Extra `csp.*` arrays are **merged into** (never replace) the base. Use
`overrides` (raw `HelmetOptions`, deep-merged last) when you must replace a whole
directive.

### Recipe: stoki (no external hosts)

```ts
import { createHelmetMiddleware } from '@andrewpopov/express-security-kit';

app.use(createHelmetMiddleware()); // strict base is exactly what stoki wants
```

### Recipe: smarthome (Redoc docs)

```ts
app.use(
  createHelmetMiddleware({
    csp: {
      scriptSrc: ['https://cdn.redoc.ly'],
      styleSrc: ['https://cdn.redoc.ly'],
    },
    overrides: { crossOriginEmbedderPolicy: false }, // Redoc needs COEP off
  }),
);
```

### Recipe: cairn (Google OAuth + Fonts)

```ts
app.use(
  createHelmetMiddleware({
    allowUnsafeInlineStyles: true, // Google button injects inline styles
    csp: {
      scriptSrc: ['https://accounts.google.com'],
      styleSrc: ['https://accounts.google.com', 'https://fonts.googleapis.com'],
      connectSrc: ['https://accounts.google.com', 'https://oauth2.googleapis.com'],
      frameSrc: ['https://accounts.google.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ['blob:'],
    },
  }),
);
```

## Module 2 — Rate limiter

`createRateLimiter(config | config[])` returns an Express handler. Pass a single
config, or an **array of tiers** applied in sequence (the first tier to exceed
its limit wins with a 429).

Config highlights:

- `windowMs`, `max` (a number, or `(req) => number` for role-aware limits)
- `algorithm`: `'fixed'` (default) or `'sliding'` (weighted current+previous)
- `keyGenerator`: default `verifiedIdentityKey` (see strategies below)
- `store`: default a shared in-process `MemoryRateLimitStore`
- `overrideResolver`: default reads `req.securityContext?.rateLimitOverride`
- `skip(req)`, `onLimit(req, key)`, `headers` (default `true`), `logger`, `now`

On a 429 it emits `RateLimit-Limit`/`RateLimit-Remaining`/`RateLimit-Reset` and
`Retry-After`, with body `{ error: { code: 'RATE_LIMITED', ... } }`. If the
store throws, the limiter **fails open** (logs a warning, allows the request) —
a rate-limit backend outage must never take down the service.

### Key-generation strategy toolkit

Keying is a composable toolkit, not a single hardcoded default:

- **`ipKey(req)`** → `ip:<req.ip>`. Coarse per-IP; use for the early flood tier.
- **`verifiedIdentityKey(req)`** (default) → `user:<principalId>` from the
  VERIFIED `req.securityContext`, else falls back to `ipKey`. Correct fair-share
  — but only meaningful when mounted **after** auth has populated the context.
- **`decodedJwtKey(opts?)`** → factory. **Decodes (does NOT verify)** the Bearer
  JWT and keys on a claim (default `sub`), falling back to `ipKey` on any
  missing/garbage token. It never throws.

  *Why decode-without-verify is OK here:* rate limiting runs *before* auth, so we
  can't yet trust the token — but keying on the claimed subject gives per-caller
  fairness for honest clients, and forged tokens are rejected downstream with 401
  before reaching the backend. **Tradeoff:** a forged token can key on a
  *victim's* id and consume their bucket, so `decodedJwtKey()` must sit **behind
  a coarse per-IP flood tier** and never be the sole limiter guarding sensitive
  fair-share. Prefer `verifiedIdentityKey` whenever you can key after auth.

> ⚠️ **IP-collapse warning.** Behind a cloudflared tunnel (or any proxy that
> terminates the connection) every request can arrive from ONE source IP. Any
> IP-based keying then collapses **all** callers into a **single** bucket.
> Configure Express `trust proxy` so `req.ip` is the real forwarded client, and
> prefer keying on a verified `principalId` for anything that matters.

### Recommended layered pattern (the mature default)

Two tiers — this is what we distribute to all services:

```ts
import { createRateLimiter, ipKey, verifiedIdentityKey } from '@andrewpopov/express-security-kit';

// Tier 1: coarse per-IP flood/DoS guard, mounted EARLY (pre-auth).
app.use(
  createRateLimiter({
    windowMs: 60_000,
    max: 600,
    keyGenerator: ipKey,
  }),
);

// ... auth middleware populates req.securityContext here ...

// Tier 2: per-principal fair-share, mounted AFTER auth.
app.use(
  '/api',
  createRateLimiter({
    windowMs: 60_000,
    max: 100,
    keyGenerator: verifiedIdentityKey,
  }),
);
```

If a service must key *before* auth runs, swap Tier 2's `keyGenerator` for
`decodedJwtKey()` — still behind Tier 1.

### Recipe: stoki (dual-tier per-key + per-IP for bot routes)

stoki's integration routes limit per API key AND per IP simultaneously. Express
this as a single dual-tier limiter (first to exceed wins):

```ts
import { createRateLimiter } from '@andrewpopov/express-security-kit';

const integrationLimiter = createRateLimiter([
  // per-key tier (principalId is the bot key id, set by api-key auth)
  {
    windowMs: 60_000,
    max: (req) => req.securityContext?.rateLimitOverride?.max ?? 240,
    keyGenerator: (req) => `key:${req.securityContext?.keyId ?? 'anon'}`,
    store: perKeyStore,
  },
  // per-IP tier (10x the per-key ceiling, guards against key sprawl)
  {
    windowMs: 60_000,
    max: 2400,
    keyGenerator: (req) => `ip:${req.ip}`,
    store: perIpStore,
  },
]);

app.use('/api/integrations', integrationLimiter);
```

Give each tier its **own store** so their counters don't collide.

### Recipe: smarthome (role-aware, Redis-backed)

```ts
import Redis from 'ioredis';
import { createRateLimiter } from '@andrewpopov/express-security-kit';
import { RedisRateLimitStore } from '@andrewpopov/express-security-kit/redis-store';

const store = new RedisRateLimitStore(new Redis(process.env.REDIS_URL));

app.use(
  createRateLimiter({
    windowMs: 60_000,
    // admins get 500/min, everyone else 100/min
    max: (req) => (req.securityContext?.principalType === 'user' &&
      isAdmin(req) ? 500 : 100),
    keyGenerator: verifiedIdentityKey,
    store,
  }),
);
```

### Recipe: cairn (per-IP auth + api limiters)

```ts
const authLimiter = createRateLimiter({
  windowMs: 15 * 60_000,
  max: process.env.NODE_ENV === 'production' ? 20 : 200,
  keyGenerator: ipKey,
});
const apiLimiter = createRateLimiter({
  windowMs: 60_000,
  max: process.env.NODE_ENV === 'production' ? 600 : 1200,
  keyGenerator: ipKey,
});

app.use(['/api/auth/login', '/api/auth/register', '/api/auth/reset-password'], authLimiter);
app.use('/api', apiLimiter);
```

### Recipe: matching your own error envelope (`message` / `buildResponseBody`)

The default 429 body is `{ error: { code: 'RATE_LIMITED', message, retryAfter } }`.
To match a different app-wide envelope (e.g. smarthome's `{ error: '<string>' }`),
pass `buildResponseBody`; to just reword the default, pass `message`:

```ts
// smarthome: whole-body override to match its { error: string } shape
createRateLimiter({
  windowMs: 60_000,
  max: 100,
  buildResponseBody: ({ retryAfterSeconds }) =>
    ({ error: `Too many requests, retry in ${retryAfterSeconds}s` }),
});

// just change the message, keep the default envelope + code
createRateLimiter({ windowMs: 60_000, max: 100, message: 'Slow down, please.' });
```

Status stays 429 and the `RateLimit-*` / `Retry-After` headers are still emitted.
A throwing `buildResponseBody` falls back to the default body (logged) — it can
never crash the middleware. Precedence: `buildResponseBody` > `message` >
default. Omit both and the body is byte-identical to prior versions.

### Recipe: only count failed attempts (`skipSuccessful`)

For an auth limiter that should only count FAILED logins (so a burst of valid
requests isn't throttled), set `skipSuccessful: true`. A request that ends with
a status `< 400` is refunded — mirroring express-rate-limit's
`skipSuccessfulRequests`:

```ts
const authLimiter = createRateLimiter({
  windowMs: 15 * 60_000,
  max: 10,                 // only 10 FAILED attempts / 15m
  keyGenerator: ipKey,
  skipSuccessful: true,    // 2xx/3xx responses are refunded, don't count
});

app.post('/api/auth/login', authLimiter, loginHandler);
```

The refund fires once when the response `finish`es with a `< 400` status. A
`close` without `finish` is an aborted request (its status isn't final — often
still the default 200) and is NOT refunded. The guard is per-limiter, so tiered
limiters each refund their own hit; a rejected (429) request is never refunded.
It uses the store's `decrement` (both built-in stores implement it) and never
throws.

## Module 3 — API-key auth

`createApiKeyAuth(config)` verifies a presented key and populates
`req.securityContext`. The kit owns the verification machinery; your service owns
persistence (`lookup`), policy (`onAuthenticated`, `requireScope`), and audit
(`onFailure`).

Pipeline: extract key (Bearer or custom header) → prefix check → constant-time
static bootstrap keys → hash + `lookup` → re-verify stored hash (defense in
depth) → expiry → IP allowlist → build context. It **fails closed**: every
failure — including a throwing `lookup` — returns a **generic** `401`/`403`
(`{ error: { code: 'UNAUTHORIZED' | 'FORBIDDEN', message } }`). The specific
reason (`missing`, `malformed`, `bad_prefix`, `not_found`, `hash_mismatch`,
`expired`, `ip_denied`, `error`) goes ONLY to your `onFailure` hook — never to
the client.

**Sharp edges worth knowing:**

- **IP allowlist is exact-match, proxy-dependent.** `allowedIps` is an EXACT
  string comparison against `req.ip` — **no CIDR or range support**. It is only
  as trustworthy as your Express `trust proxy` setting: a too-broad
  `trust proxy` lets a client spoof `X-Forwarded-For` and defeat the allowlist.
  `'*'` disables the check; an undefined `req.ip` is denied unless `''` is
  explicitly listed.
- **`optional` mode is narrow.** Only a genuinely ABSENT credential (no/empty
  header) passes through as anonymous. A PRESENT-but-malformed credential
  (`Authorization: Basic x`, a bare `Bearer`) is a failed auth attempt and still
  returns 401.
- **Invalid expiry = expired.** A corrupt `expiresAt` (an Invalid Date) is
  treated as expired, never as "no expiry".
- **Audit hooks must not respond.** `onFailure` (and `requireScope`'s
  `onDenied`) may be async; a returned promise's rejection is caught and logged.
  They must NOT send a response — the middleware owns the 401/403.
- **`requireScope` predicates must be synchronous.** Only a literal `true`
  proceeds; a returned Promise is treated as misuse and denies (403).

### Recipe: cairn (`cairn_` + sha256 + bot-user)

```ts
import { createApiKeyAuth, sha256Hasher } from '@andrewpopov/express-security-kit';

app.use(
  '/api/bot',
  createApiKeyAuth({
    prefix: 'cairn_',
    hasher: sha256Hasher(), // default; shown for clarity
    lookup: (hash) => db.apiKey.findByHash(hash), // returns ApiKeyRecord | null
    // Mint a first-class bot USER context instead of a bare apiKey principal.
    onAuthenticated: async (_req, key) => {
      const bot = await db.botUser.forKey(key.id);
      return {
        principalType: 'user',
        principalId: bot.id,
        keyId: key.id,
        scopes: { org: bot.orgId, projects: bot.projectIds },
      };
    },
    onFailure: (req, reason) => auditLog.warn('apikey_denied', { ip: req.ip, reason }),
  }),
);
```

### Recipe: smarthome (`smh_` + scopedHmac + static bootstrap)

```ts
import { createApiKeyAuth, scopedHmacHasher } from '@andrewpopov/express-security-kit';

app.use(
  '/api',
  createApiKeyAuth({
    prefix: 'smh_',
    // EXACT reproduction of smarthome's existing stored-key format:
    hasher: scopedHmacHasher(process.env.KEY_SECRET!, 'integrations'),
    lookup: (hash) => keyStore.find(hash),
    // A CI/bootstrap key kept in an env var, authenticated as a service:
    staticKeys: [
      { name: 'bootstrap', value: process.env.SMH_BOOTSTRAP_KEY!, principalId: 'svc:bootstrap' },
    ],
  }),
);
```

### Recipe: stoki (`ssk_ak_` + sha256 + scopes gate)

```ts
import { createApiKeyAuth, requireScope } from '@andrewpopov/express-security-kit';

app.use('/api/integrations', createApiKeyAuth({
  prefix: 'ssk_ak_',
  lookup: (hash) => keys.byHash(hash), // record.scopes = { allowedActions: [...] }
}));

// requireScope ships only the MECHANISM; the predicate is stoki's policy.
const canWrite = requireScope((ctx) => {
  const actions = (ctx?.scopes as { allowedActions?: string[] } | undefined)?.allowedActions;
  return Array.isArray(actions) && actions.includes('write');
});

app.post('/api/integrations/sync', canWrite, syncHandler);
```

`record.rateLimitOverride` flows straight into the rate limiter's default
override resolver, so a per-key limit set at issue time is honored automatically
by a downstream `createRateLimiter`.

### Unified / multi-method auth (`verifyApiKey`)

If a service authenticates requests by trying an API key FIRST and falling back
to JWT (cairn, likely stoki), use the verify-only primitive `verifyApiKey` — it
returns a decision instead of sending a response, keeping the kit out of your
response handling and your JWT path:

```ts
import { verifyApiKey } from '@andrewpopov/express-security-kit';

const apiKeyConfig = { prefix: 'cairn_', headerName: 'x-api-key', lookup };

app.use(async (req, res, next) => {
  const outcome = await verifyApiKey(apiKeyConfig, req);

  if (outcome.ok) {
    req.securityContext = outcome.context;   // e.g. outcome.context.meta.orgId
    return next();
  }

  // `present` is false ONLY when NO api-key credential was supplied — fall
  // through to the service's own JWT auth. A present-but-invalid key is a real
  // failed attempt, so reject it rather than silently trying JWT.
  if (!outcome.present) {
    return authenticateJwt(req, res, next);
  }

  return res.status(outcome.status).json({ error: { code: 'UNAUTHORIZED' } });
});
```

`verifyApiKey` never throws (unexpected errors fail closed to
`{ ok: false, reason: 'error', present: true, status: 401 }`), never touches
`res` or `req.securityContext`, and — for a matched key — returns the `record`
so you can read fields your `lookup` stashed (including `record.meta`).
`createApiKeyAuth` is itself just a thin middleware over `verifyApiKey`.

## Module 4 — HMAC request signing + replay protection

**Opt-in.** For high-value machine-to-machine routes you can require that each
request be HMAC-signed and single-use. `createRequestSigningVerifier(config)`
verifies the signature and consumes the nonce; `signRequest(...)` is the
client-side helper that produces compatible headers. The scheme is byte-for-byte
compatible with stoki's existing signed clients.

### The scheme

Canonical string = five LF-joined lines:

```
METHOD (uppercase)
originalUrl (path + query, exactly as received)
timestampMs
nonce
sha256hex(body)          # GET/HEAD → sha256hex('')
```

Signature = `HMAC-SHA256(secret, canonical)` as lowercase hex, sent as
`X-Signature` with `X-Timestamp` (ms epoch) and `X-Nonce`.

### Client side

```ts
import { signRequest } from '@andrewpopov/express-security-kit';

const { headers } = signRequest({
  secret,
  method: 'POST',
  url: '/api/lists/abc123/items?sort=name', // must equal server's req.originalUrl
  timestampMs: Date.now(),
  nonce: crypto.randomUUID(),               // matches /^[A-Za-z0-9:_-]{8,128}$/
  body: rawJsonStringYouActuallySend,       // the EXACT bytes on the wire
});
// send headers['X-Timestamp' | 'X-Nonce' | 'X-Signature'] with the request
```

### Server side — per-key secret (recommended)

```ts
import {
  createRequestSigningVerifier,
  MemoryNonceStore,
} from '@andrewpopov/express-security-kit';

const nonceStore = new MemoryNonceStore(); // per-process — see caveat below

app.use('/api/signed', createRequestSigningVerifier({
  // The api-key verifier ran first and set securityContext.hmacSecret.
  secret: (_req, ctx) => ctx?.hmacSecret ?? undefined, // undefined → fail closed
  nonceStore,
  maxSkewSeconds: 300, // clamped to [30, 900]
  onFailure: (req, reason) => auditLog.warn('signing_denied', { reason, ip: req.ip }),
}));
```

### Server side — global secret

```ts
app.use('/api/webhook', createRequestSigningVerifier({
  secret: process.env.WEBHOOK_SIGNING_SECRET!, // static shared secret
  nonceStore,
}));
```

### ⚠️ rawBody capture is REQUIRED for signed bodies

The verifier hashes the request body. By default it uses `req.rawBody` — the
**exact bytes received** — and only falls back to `JSON.stringify(req.body)` if
that is absent. **`JSON.stringify` of a parsed object is NOT guaranteed to equal
the client's original bytes** (key ordering, whitespace, unicode escaping,
number formatting all differ), so without rawBody, signature checks on JSON
bodies can spuriously fail. Capture rawBody with express.json's `verify` hook:

```ts
app.use(express.json({
  verify: (req, _res, buf) => { (req as any).rawBody = buf; },
}));
```

GET/HEAD requests have no body (hashed as `''`), so they don't need this.

Set `requireRawBody: true` to FAIL CLOSED (reason `no_raw_body`) on a
body-bearing request (never GET/HEAD) that arrives without `req.rawBody`,
instead of silently falling back to `JSON.stringify(req.body)`. Default
`false` (unchanged behavior). Only governs the default extractor — a custom
`bodySource` participates as provided.

### Replay protection & the nonce store

After the signature is proven valid (and before `next()`), the nonce is consumed
via `nonceStore.consume(scope, nonce, ttlMs)` where `ttlMs` = the skew window.
A second use of the same nonce within that window → 401. The `scope` defaults to
`ctx.keyId ?? ctx.principalId ?? 'global'`, so one key's nonces never collide
with another's.

> **`MemoryNonceStore` is PER-PROCESS.** In a clustered / multi-instance
> deployment it provides NO cross-instance replay protection — a replay routed
> to a different instance won't be detected. Inject a **persistent shared store**
> (Prisma, Redis, …) implementing the `NonceStore` interface
> (`consume(scope, nonce, ttlMs): Promise<'ok' | 'replay'>`) for those
> deployments. A thrown/rejected `consume` makes the verifier **fail closed**.

## Module 5 — Buffered audit

`AuditBuffer` batches audit events off the request path to an injected
`AuditSink`. The kit owns buffering/batching/flush/backpressure + event
normalization; the SERVICE injects the sink (persistence) and decides what is
auditable. `record()` is non-blocking and NEVER throws — a broken sink can never
break a request.

### (a) Inject a durable sink

```ts
import { AuditBuffer, type AuditSink } from '@andrewpopov/express-security-kit';

const prismaSink: AuditSink = {
  async write(events) {
    await prisma.auditLog.createMany({ data: events }); // one batched insert
  },
};

const audit = new AuditBuffer({
  sink: prismaSink,
  maxBufferSize: 100,     // flush when this many events are buffered (> 0)
  flushIntervalMs: 5000,  // ...or every 5s, whichever first
  maxQueueSize: 10000,    // hard cap; excess drops OLDEST (counted) (> 0)
  closeMaxRetries: 3,     // bounded flush retries during close() on sink failure
  onDropped: (n) => metrics.increment('audit.dropped', n),
  onFlushError: (err) => log.error('audit sink failed; will retry', err),
});
```

| Option | Default | Notes |
|---|---|---|
| `maxBufferSize` | 100 | Flush once this many events are buffered. Must be > 0. |
| `flushIntervalMs` | 5000 | Periodic flush interval (`.unref()`'d timer). ≤ 0 disables the timer. |
| `maxQueueSize` | 10000 | Hard cap; excess drops OLDEST (counted via `onDropped`). Must be > 0. |
| `closeMaxRetries` | 3 | Extra flush attempts during `close()` when the sink is failing, with a short delay between. Beyond this, undrained events stay queued (surfaced via `onFlushError`) rather than hanging shutdown. |

> **At-least-once delivery.** On a transient sink error the WHOLE failed batch is
> re-queued and retried, so a custom sink may see the same event more than once.
> Make `sink.write` **atomic or idempotent** (e.g. upsert on a unique event id).
> `ConsoleAuditSink` guards each event independently so one un-serializable event
> can't fail — and thus re-emit — the rest of a batch.

`ConsoleAuditSink` (JSON lines) is a dev default — **production should inject a
durable sink** (Prisma / append-only file / log-shipping HTTP).

### (b) Wire audit into every pillar with one shared buffer

```ts
import {
  auditFailureHook, auditRateLimitHook, auditDeniedHook,
} from '@andrewpopov/express-security-kit';

app.use(createRateLimiter({
  windowMs: 60_000, max: 600, keyGenerator: ipKey,
  onLimit: auditRateLimitHook(audit, 'ratelimit.ip'),
}));

app.use(createApiKeyAuth({
  prefix: 'ssk_ak_',
  lookup,
  onFailure: auditFailureHook(audit, 'apiKey.auth'),        // (req, reason) => void
}));

app.use('/api/signed', createRequestSigningVerifier({
  secret: (_req, ctx) => ctx?.hmacSecret ?? undefined,
  nonceStore,
  onFailure: auditFailureHook(audit, 'signing.verify'),     // records the reason
}));

app.post('/api/admin/x',
  requireScope(canAdmin, { onDenied: auditDeniedHook(audit, 'scope.admin') }),
  adminHandler,
);
```

Each hook records a normalized `AuditEvent` (principal/ip/method/path pulled from
`req.securityContext` + the request). You can also record success events by hand
with `buildAuditEvent(req, { action, outcome: 'allow' })`.

### (c) Flush on shutdown

```ts
process.on('SIGTERM', async () => {
  server.close();
  await audit.close(); // stops the timer and drains remaining events
  process.exit(0);
});
```

> **Backpressure & durability.** The queue is hard-capped — a sustained sink
> outage drops the OLDEST events (counted via `onDropped`) rather than growing
> unbounded. On a transient sink error the failed batch is re-queued at the
> front and retried on the next flush. Events buffered in memory are lost on a
> hard crash; a durable sink minimizes the window, and `close()` drains on
> graceful shutdown.

## Stores

- **`MemoryRateLimitStore`** (default) — single-process, Map-based, bounded by
  `maxTrackedKeys` with drop-oldest eviction and an `unref`'d cleanup timer.
  Call `.stop()` / `.dispose()` in tests to clear the timer.
- **`RedisRateLimitStore`** — for multi-instance deployments. Imported ONLY from
  the `@andrewpopov/express-security-kit/redis-store` subpath; the main entry
  never references ioredis, so the core stays dependency-free. Bucket keys are
  `<keyPrefix>:<key>:<windowMs>:<windowIndex>` (namespaced by window length,
  same as `MemoryRateLimitStore`). When the client implements `eval` (real
  ioredis always does), `hit()` runs ONE atomic Lua round trip — INCR, then
  (re)arm the TTL only if none is set (`PTTL < 0`), then GET the previous
  bucket — so a crash between INCR and PEXPIRE can no longer leave a
  never-expiring key, and the script self-heals any key already leaked by an
  older version. Pass `reset(key, windowMs)` for an EXACT reset of that
  window's buckets.

  > ⚠️ **`reset(key)` without `windowMs`.** Omitting `windowMs` falls back to a
  > fixed set of common window sizes (1s, 1m, 15m, 1h, 1d) rather than a
  > heavier SCAN. If your limiter uses a **custom** `windowMs` not in that
  > list, pass it explicitly (`reset(key, windowMs)`) for a precise reset —
  > otherwise those buckets are **not** cleared and the key stays limited
  > until the window naturally expires. `MemoryRateLimitStore.reset()` has no
  > such limit either way.

```ts
import { RedisRateLimitStore } from '@andrewpopov/express-security-kit/redis-store';
const store = new RedisRateLimitStore(redisClient);
```

## The `SecurityContext` type

Upstream auth middleware (later phases) attaches this to the request; Phase 1
modules only **read** it:

```ts
interface SecurityContext {
  principalType: 'apiKey' | 'user' | 'service' | 'anonymous';
  principalId?: string;
  keyId?: string;
  scopes?: unknown;
  rateLimitOverride?: { windowMs: number; max: number };
}
```

Importing this package augments Express's `Request` with an optional
`securityContext?: SecurityContext`.

## License

MIT © Andrew Popov
