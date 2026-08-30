---
kind: added
summary: New export createRequestSignatureVerifierCore: the HMAC request-signature verification decision, carved into the framework-agnostic core.
---

The kit's catalog role is "framework-agnostic core + Express adapters", but
signing broke that: `@andrewpopov/express-security-kit/core` could `signRequest`
but not verify one — every check (secret resolution, timestamp/skew, nonce
format, signature recomputation, and replay-protected nonce consumption) lived
inside `createRequestSigningVerifier`, pinned to an Express `RequestHandler`.
`createRequestSignatureVerifierCore()` carves that decision out, mirroring the
PKG-107 rate-limit carve: `verify(input)` takes plain data — method, url, the
three header values, the body string, the resolved secret, the nonce scope,
and whether a raw body was present — and returns `{ type: 'ok' }` or
`{ type: 'fail', reason }`, performing the exact same ordered checks and
fail-closed semantics as before (crucially, the nonce is still consumed only
AFTER the signature is proven valid, and a nonce-store throw or an
unrecognized store result still fails closed). `createRequestSigningVerifier`
is now a thin Express adapter over this core — same public config, same
behaviour, same tests, unmodified and passing. This is what lets a Fastify (or
any other) adapter reuse the exact verification logic instead of
reimplementing HMAC/replay checking from scratch.
