---
kind: fixed
summary: The documented API-key recipe (mint with generateApiKey, verify by public keyId) now actually works: createCanonicalRawAuthenticator implements it, and rawAuthenticator configs no longer need a dead lookup callback.
---

Previously, a key minted with `generateApiKey` (which stores `hash =
hasher(secret)`, the secret segment only) always failed verification through
the documented `lookup`-based recipe, because the legacy verifier compares
against `hasher(rawKey)` — the whole wire credential. The README's own
suggested remedy ("parse, look up by the public keyId...") could not actually
be expressed, since `lookup` receives only a computed hash, never the raw key.
`createCanonicalRawAuthenticator` is the real implementation of that recipe:
wire it into `rawAuthenticator` and a `generateApiKey`-minted key now
authenticates end to end. The legacy `lookup`/`hasher` path is unchanged and
still supported for existing stores.
