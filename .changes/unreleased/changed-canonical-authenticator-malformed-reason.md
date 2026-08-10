---
kind: changed
summary: createCanonicalRawAuthenticator now reports reason: 'malformed' for a structurally invalid key (no '.' separator), instead of collapsing it into 'not_found' alongside an unknown keyId.
---

Previously, `createCanonicalRawAuthenticator` mapped EVERY unverifiable key —
a structurally malformed one (missing the required `.` separator) and a
well-formed one nobody issued — to the same `not_found` reason, because
`RawApiKeyAuthentication` had no `malformed` member to report. It now reports
`malformed` for the structural case, distinct from `not_found` for a genuine
unknown keyId. `RawApiKeyAuthentication.reason` is widened accordingly
(`bad_prefix` stays excluded — that reason remains reserved for
`verifyApiKey`'s own upstream prefix check).

**The client-visible response is unchanged: still a generic 401 either way.**
This is an observability improvement only — monitoring and `onFailure` can
now tell "a client is sending structurally broken credentials" (usually a
client bug or a truncated secret) apart from "a client is presenting keys we
never issued" (usually revocation or probing), which warrant different
operational responses. Nothing leaks and nothing is mis-authorized. A custom
`rawAuthenticator` you've written yourself is unaffected — this only changes
`createCanonicalRawAuthenticator`'s own mapping and the type it's now allowed
to report through.
