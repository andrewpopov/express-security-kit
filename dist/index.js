"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeOrigin = exports.resolveCorsPolicy = exports.createWebhookVerifier = exports.verifyWebhookSignature = exports.auditDeniedHook = exports.auditRateLimitHook = exports.auditFailureHook = exports.buildAuditEvent = exports.ConsoleAuditSink = exports.AuditBuffer = exports.MemoryNonceStore = exports.createRequestSigningVerifier = exports.sha256Hex = exports.signRequest = exports.buildCanonicalString = exports.createThrottledTouchLastUsed = exports.rotateApiKey = exports.maskApiKey = exports.parseApiKey = exports.generateApiKey = exports.normalizeIp = exports.requireScope = exports.timingSafeEqualHex = exports.scopedHmacHasher = exports.sha256Hasher = exports.verifyApiKey = exports.createApiKeyAuth = exports.decodedJwtKey = exports.defaultKeyGenerator = exports.verifiedIdentityKey = exports.ipKey = exports.MemoryRateLimitStore = exports.createRateLimiter = exports.createHelmetMiddleware = void 0;
// Side-effect import: merges the `securityContext`/`rawBody` fields onto the
// ambient `Express.Request` type. MUST be a value import (not `import type`)
// so the augmentation is actually loaded by root consumers.
require("./express/augmentation");
// Root re-exports pin the request type to express `Request` so the PUBLIC
// signatures — including type-level introspection via `Parameters<>` /
// `ReturnType<>` — match v1.0.0 exactly. The `./core` subpath keeps the generic
// `<Req extends SecurityRequest = SecurityRequest>` forms for framework-agnostic
// consumers. Values are re-exported through a pinned-type `const` binding, so the
// underlying function identity (and thus behavior) is unchanged.
// Shorthand re-exports (no renaming) so cjs-module-lexer statically detects the
// named exports for ESM consumers of the CommonJS build.
var createHelmetMiddleware_1 = require("./express/helmet/createHelmetMiddleware");
Object.defineProperty(exports, "createHelmetMiddleware", { enumerable: true, get: function () { return createHelmetMiddleware_1.createHelmetMiddleware; } });
var createRateLimiter_1 = require("./express/rate-limit/createRateLimiter");
Object.defineProperty(exports, "createRateLimiter", { enumerable: true, get: function () { return createRateLimiter_1.createRateLimiter; } });
var store_1 = require("./core/rate-limit/store");
Object.defineProperty(exports, "MemoryRateLimitStore", { enumerable: true, get: function () { return store_1.MemoryRateLimitStore; } });
// Key generators: pinned to express `Request` at the root (generic in ./core).
const keyGenerator_1 = require("./core/rate-limit/keyGenerator");
exports.ipKey = keyGenerator_1.ipKey;
exports.verifiedIdentityKey = keyGenerator_1.verifiedIdentityKey;
exports.defaultKeyGenerator = keyGenerator_1.defaultKeyGenerator;
exports.decodedJwtKey = keyGenerator_1.decodedJwtKey;
var createApiKeyAuth_1 = require("./express/api-key/createApiKeyAuth");
Object.defineProperty(exports, "createApiKeyAuth", { enumerable: true, get: function () { return createApiKeyAuth_1.createApiKeyAuth; } });
// verifyApiKey: pinned to `(config, req: Request)` — the v1.0.0 signature.
const verifyApiKey_1 = require("./core/api-key/verifyApiKey");
exports.verifyApiKey = verifyApiKey_1.verifyApiKey;
var hashers_1 = require("./core/api-key/hashers");
Object.defineProperty(exports, "sha256Hasher", { enumerable: true, get: function () { return hashers_1.sha256Hasher; } });
Object.defineProperty(exports, "scopedHmacHasher", { enumerable: true, get: function () { return hashers_1.scopedHmacHasher; } });
Object.defineProperty(exports, "timingSafeEqualHex", { enumerable: true, get: function () { return hashers_1.timingSafeEqualHex; } });
var requireScope_1 = require("./express/api-key/requireScope");
Object.defineProperty(exports, "requireScope", { enumerable: true, get: function () { return requireScope_1.requireScope; } });
var normalizeIp_1 = require("./core/api-key/normalizeIp");
Object.defineProperty(exports, "normalizeIp", { enumerable: true, get: function () { return normalizeIp_1.normalizeIp; } });
// API-key ISSUANCE (mint/parse/mask/rotate). Framework-agnostic — no Request
// pinning needed, unlike verifyApiKey/createApiKeyAuth above.
var issuance_1 = require("./core/api-key/issuance");
Object.defineProperty(exports, "generateApiKey", { enumerable: true, get: function () { return issuance_1.generateApiKey; } });
Object.defineProperty(exports, "parseApiKey", { enumerable: true, get: function () { return issuance_1.parseApiKey; } });
Object.defineProperty(exports, "maskApiKey", { enumerable: true, get: function () { return issuance_1.maskApiKey; } });
Object.defineProperty(exports, "rotateApiKey", { enumerable: true, get: function () { return issuance_1.rotateApiKey; } });
Object.defineProperty(exports, "createThrottledTouchLastUsed", { enumerable: true, get: function () { return issuance_1.createThrottledTouchLastUsed; } });
var signRequest_1 = require("./core/signing/signRequest");
Object.defineProperty(exports, "buildCanonicalString", { enumerable: true, get: function () { return signRequest_1.buildCanonicalString; } });
Object.defineProperty(exports, "signRequest", { enumerable: true, get: function () { return signRequest_1.signRequest; } });
Object.defineProperty(exports, "sha256Hex", { enumerable: true, get: function () { return signRequest_1.sha256Hex; } });
var createRequestSigningVerifier_1 = require("./express/signing/createRequestSigningVerifier");
Object.defineProperty(exports, "createRequestSigningVerifier", { enumerable: true, get: function () { return createRequestSigningVerifier_1.createRequestSigningVerifier; } });
var nonceStore_1 = require("./core/signing/nonceStore");
Object.defineProperty(exports, "MemoryNonceStore", { enumerable: true, get: function () { return nonceStore_1.MemoryNonceStore; } });
var AuditBuffer_1 = require("./core/audit/AuditBuffer");
Object.defineProperty(exports, "AuditBuffer", { enumerable: true, get: function () { return AuditBuffer_1.AuditBuffer; } });
var ConsoleAuditSink_1 = require("./core/audit/ConsoleAuditSink");
Object.defineProperty(exports, "ConsoleAuditSink", { enumerable: true, get: function () { return ConsoleAuditSink_1.ConsoleAuditSink; } });
// buildAuditEvent + audit hooks: pinned to express `Request` at the root.
const buildAuditEvent_1 = require("./core/audit/buildAuditEvent");
exports.buildAuditEvent = buildAuditEvent_1.buildAuditEvent;
const hooks_1 = require("./core/audit/hooks");
exports.auditFailureHook = hooks_1.auditFailureHook;
exports.auditRateLimitHook = hooks_1.auditRateLimitHook;
exports.auditDeniedHook = hooks_1.auditDeniedHook;
// ---------------------------------------------------------------------------
// Phase 2 (v1.2.0) modules, also re-exported from root as of v1.2.1 for
// consistency with the other Express middleware above. Purely additive: the
// `./webhook`, `./express/webhook`, `./cors`, and `./express/cors` subpaths
// are unchanged.
// Webhook signature verification. `verifyWebhookSignature` is already
// framework-agnostic (it takes a plain `WebhookHeaders` record, not
// `Request`) and `createWebhookVerifier` is already Express-only, so both are
// safe direct re-exports here — no Request-pinning wrapper needed.
var verify_1 = require("./core/webhook/verify");
Object.defineProperty(exports, "verifyWebhookSignature", { enumerable: true, get: function () { return verify_1.verifyWebhookSignature; } });
var createWebhookVerifier_1 = require("./express/webhook/createWebhookVerifier");
Object.defineProperty(exports, "createWebhookVerifier", { enumerable: true, get: function () { return createWebhookVerifier_1.createWebhookVerifier; } });
// CORS origin-resolution policy. Framework-agnostic — no `cors`/express
// dependency — so it's a safe direct re-export.
var policy_1 = require("./core/cors/policy");
Object.defineProperty(exports, "resolveCorsPolicy", { enumerable: true, get: function () { return policy_1.resolveCorsPolicy; } });
Object.defineProperty(exports, "normalizeOrigin", { enumerable: true, get: function () { return policy_1.normalizeOrigin; } });
// `corsOptions` (the `cors` package adapter) deliberately STAYS on the
// `./express/cors` subpath only — NOT re-exported here. Its return type is
// `CorsOptions` from the `cors` package (a type-only import in
// ./express/cors/corsOptions.ts); re-exporting it from root pulls that type
// into dist/index.d.ts, so ANY root consumer's TS compile must resolve
// `@types/cors` even if they never touch CORS. Verified via `verify:pack`:
// a consumer that installs `express` (root's own peer) but NOT `cors`/
// `@types/cors` fails to type-check `import { corsOptions } from '<pkg>'`
// with `TS2307: Cannot find module 'cors'`. `resolveCorsPolicy` and
// `normalizeOrigin` above have no such dependency and are safe on root.
// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
