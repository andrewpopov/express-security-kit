---
kind: breaking
summary: createApiKeyAuth (Express and Fastify) now throws synchronously at construction if config supplies NEITHER rawAuthenticator nor lookup. Supplying BOTH is unaffected — see the separate deprecation note.
---

`ApiKeyAuthConfigCore.lookup` is now optional: a canonical config
(`rawAuthenticator` only) no longer needs a dead `lookup` callback just to
satisfy the type. The only construction-time rejection is a config that
supplies **neither** `rawAuthenticator` nor `lookup` — a shape that cannot
authenticate under any code path.

This case was already fully broken: on master today, "neither supplied"
already fails every request with `reason: 'error'`/503, via an uncaught
`TypeError` from calling `undefined` as `lookup`, swallowed by
`verifyApiKey`'s fail-closed catch-all. Nothing that could serve traffic
relies on this shape. The only change is *when* the failure surfaces —
`createApiKeyAuth` now throws a descriptive `Error` immediately at
construction (fail fast, at boot) instead of deferring to the first request.
`verifyApiKey`, used directly, is unchanged: it still never throws and still
resolves to `{ reason: 'error', status: 503 }` for this shape.

Supplying **both** `rawAuthenticator` and `lookup` is explicitly NOT rejected
— see the separate `changed` note in this release for that behavior.
