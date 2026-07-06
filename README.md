# @andrewpopov/express-security-kit

A dependency-light Express security library. It owns the **machinery**;
consuming services inject all **policy**. Phase 1 ships two modules — a hardened
**helmet preset** and a **rate limiter** — plus a shared `SecurityContext` type.

> API-key auth, HMAC request signing, and audit logging are LATER phases and are
> intentionally NOT in this package yet.

The core has **zero runtime dependencies**. `express` and `helmet` are peer
dependencies you already have; `ioredis` is an *optional* peer needed only if
you use the Redis store subpath.

## Install

This package is distributed via GitHub tags (not npm):

```bash
npm install github:andrewpopov/express-security-kit#v0.1.0
```

Peers (you almost certainly already have these):

```bash
npm install express helmet
# only if you use the Redis store:
npm install ioredis
```

## Middleware ordering

Mount in this order. Later phases slot in where marked:

```
helmet  →  rate-limit (Tier 1: per-IP flood)  →  api-key auth  →
rate-limit (Tier 2: per-principal)  →  [request signing]  →  routes
```

Security headers first, then a coarse flood guard *before* you spend CPU on auth,
then the API-key verifier (which populates `req.securityContext`), then
identity-aware fair-share limiting *after* that context exists. `[request
signing]` is Phase 3.

> **Fail direction differs by layer.** The rate limiter **fails open** (a store
> outage must not take the service down); the API-key verifier **fails closed**
> (any error → generic 401, request denied). That's intentional.

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

## Stores

- **`MemoryRateLimitStore`** (default) — single-process, Map-based, bounded by
  `maxTrackedKeys` with drop-oldest eviction and an `unref`'d cleanup timer.
  Call `.stop()` / `.dispose()` in tests to clear the timer.
- **`RedisRateLimitStore`** — for multi-instance deployments. Imported ONLY from
  the `@andrewpopov/express-security-kit/redis-store` subpath; the main entry
  never references ioredis, so the core stays dependency-free.

  > ⚠️ **`reset()` limitation.** The store interface gives `reset(key)` no window
  > length, so `RedisRateLimitStore.reset()` only clears buckets for a fixed set
  > of common window sizes (1s, 1m, 15m, 1h, 1d). If your limiter uses a
  > **custom** `windowMs` not in that list, its buckets are **not** cleared and
  > the key stays limited until the window naturally expires — delete the bucket
  > keys yourself (`<keyPrefix>:<key>:<floor(now/windowMs)>` and the prior index)
  > if you need an exact reset. `MemoryRateLimitStore.reset()` has no such limit.

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
