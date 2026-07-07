# Migrating hand-rolled security code to the kit

A mapping from common hand-rolled patterns to the kit's modules, plus the two
gotchas that bite almost everyone on the first pass.

## Mapping

| Hand-rolled pattern | Kit replacement |
|---|---|
| `express-rate-limit` (or a custom counter) | `createRateLimiter({ windowMs, max, keyGenerator, store })` — supports fixed/sliding algorithms, tiered configs, and a pluggable store (`MemoryRateLimitStore` / `RedisRateLimitStore`). |
| Ad-hoc `x-api-key` header check | `createApiKeyAuth({ prefix, hasher, lookup })` (middleware, fails closed) or `verifyApiKey(config, req)` (verify-only primitive) if you need to fall through to another auth method. |
| Bespoke HMAC request signing | `signRequest(...)` (client-side helper) + `createRequestSigningVerifier({ secret, nonceStore })` (server-side, replay-protected). Byte-for-byte compatible with stoki's existing scheme. |
| Scattered `console.log`/custom audit calls | `AuditBuffer` + `auditFailureHook` / `auditRateLimitHook` / `auditDeniedHook`, wired into each pillar's `onFailure`/`onLimit`/`onDenied`. |
| Manual `helmet()` config | `createHelmetMiddleware(config?)` — strict CSP base, widen only what you need. |

## Gotcha 1: `rawBody` capture for signed bodies

`createRequestSigningVerifier` hashes the request body as part of the
canonical string. By default it reads `req.rawBody` (the exact bytes
received) and only falls back to `JSON.stringify(req.body)` if that's absent
— but `JSON.stringify` of a parsed object is **not guaranteed** to match the
client's original bytes (key order, whitespace, number formatting, unicode
escaping can all differ), which causes spurious signature failures on JSON
bodies. Capture it via `express.json`'s `verify` hook, mounted BEFORE the
signing verifier:

```ts
app.use(express.json({
  verify: (req, _res, buf) => { (req as any).rawBody = buf; },
}));
```

If you'd rather fail loudly than silently mis-hash, set
`requireRawBody: true` (0.7.0+) — body-bearing requests without `rawBody`
get a `401` (`no_raw_body`) instead of a maybe-wrong signature check.
GET/HEAD never need this (no body).

## Gotcha 2: `trust proxy`

Both the rate limiter's IP-based keying (`ipKey`) and the API-key verifier's
`allowedIps` read `req.ip`, which Express only reports correctly when
`app.set('trust proxy', ...)` matches your actual deployment topology:

- **Too narrow** (default, no proxy configured) behind a real proxy/tunnel:
  `req.ip` is the proxy's address, not the client's — every request looks
  like it comes from one IP, collapsing all callers into a single rate-limit
  bucket and making `allowedIps` useless.
- **Too broad** (e.g. blindly trusting `X-Forwarded-For`): a client can spoof
  its apparent IP and defeat both the rate limiter's fairness and the
  API-key allowlist.

Set `trust proxy` to match exactly how many hops of proxy you actually have
(a number, or a specific subnet/list) — not `true`.
