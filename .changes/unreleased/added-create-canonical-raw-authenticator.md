---
kind: added
summary: New export createCanonicalRawAuthenticator: a generic RawApiKeyAuthenticator adapter (parse the presented key, look up by public keyId, constant-time compare the secret-segment hash) that any host can wire to its own store.
---

Give it a `prefix` and a `findByKeyId(keyId)` lookup and it does the rest:
parse `<prefix><keyId>.<secret>`, look up the record by the PUBLIC keyId
(indexed, never a table scan), and constant-time compare the stored hash
against `hasher(secret)` — the hash of the secret segment alone, exactly what
`generateApiKey` stores. Fails closed and preserves the existing failure-reason
vocabulary (`not_found`, `hash_mismatch`, `unavailable`); a throwing
`findByKeyId` maps to `'unavailable'` (reported at `errorStatus`, default 503),
never a 401. No runtime dependency on any other package — wire it to any
store, including one backed by `@andrewpopov/api-access-kit`.

An unknown keyId is not a short-circuit: it still runs the same `hasher` +
constant-time-compare work a known keyId would, against a fixed dummy hash
computed once per authenticator (never per request, never derived from
anything a caller supplies) — the same `dummyHash` pattern `auth-kit` uses
(PKG-137). Without this, `findByKeyId` returning `null` would be a key-ID
existence oracle: observable via timing, and — more reliably, with no timing
measurement at all — via *reason*, since a throwing `hasher` would otherwise
401 (`not_found`) an unknown keyId but 503 (`unavailable`) a known one. A
throwing `hasher` now maps to `'unavailable'` (an infrastructure fault, not an
auth decision) identically for both, closing that gap.
