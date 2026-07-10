"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditDeniedHook = exports.auditRateLimitHook = exports.auditFailureHook = exports.ConsoleAuditSink = exports.buildAuditEvent = exports.AuditBuffer = exports.MemoryNonceStore = exports.createRequestSigningVerifier = exports.sha256Hex = exports.signRequest = exports.buildCanonicalString = exports.requireScope = exports.timingSafeEqualHex = exports.scopedHmacHasher = exports.sha256Hasher = exports.verifyApiKey = exports.createApiKeyAuth = exports.decodedJwtKey = exports.verifiedIdentityKey = exports.ipKey = exports.defaultKeyGenerator = exports.MemoryRateLimitStore = exports.createRateLimiter = exports.createHelmetMiddleware = void 0;
// Side-effect import: merges the `securityContext`/`rawBody` fields onto the
// ambient `Express.Request` type. MUST be a value import (not `import type`)
// so the augmentation is actually loaded by root consumers.
require("./express/augmentation");
// Shorthand re-exports (no renaming) so cjs-module-lexer statically detects the
// named exports for ESM consumers of the CommonJS build.
var createHelmetMiddleware_1 = require("./express/helmet/createHelmetMiddleware");
Object.defineProperty(exports, "createHelmetMiddleware", { enumerable: true, get: function () { return createHelmetMiddleware_1.createHelmetMiddleware; } });
var createRateLimiter_1 = require("./express/rate-limit/createRateLimiter");
Object.defineProperty(exports, "createRateLimiter", { enumerable: true, get: function () { return createRateLimiter_1.createRateLimiter; } });
var store_1 = require("./core/rate-limit/store");
Object.defineProperty(exports, "MemoryRateLimitStore", { enumerable: true, get: function () { return store_1.MemoryRateLimitStore; } });
var keyGenerator_1 = require("./core/rate-limit/keyGenerator");
Object.defineProperty(exports, "defaultKeyGenerator", { enumerable: true, get: function () { return keyGenerator_1.defaultKeyGenerator; } });
Object.defineProperty(exports, "ipKey", { enumerable: true, get: function () { return keyGenerator_1.ipKey; } });
Object.defineProperty(exports, "verifiedIdentityKey", { enumerable: true, get: function () { return keyGenerator_1.verifiedIdentityKey; } });
Object.defineProperty(exports, "decodedJwtKey", { enumerable: true, get: function () { return keyGenerator_1.decodedJwtKey; } });
var createApiKeyAuth_1 = require("./express/api-key/createApiKeyAuth");
Object.defineProperty(exports, "createApiKeyAuth", { enumerable: true, get: function () { return createApiKeyAuth_1.createApiKeyAuth; } });
var verifyApiKey_1 = require("./core/api-key/verifyApiKey");
Object.defineProperty(exports, "verifyApiKey", { enumerable: true, get: function () { return verifyApiKey_1.verifyApiKey; } });
var hashers_1 = require("./core/api-key/hashers");
Object.defineProperty(exports, "sha256Hasher", { enumerable: true, get: function () { return hashers_1.sha256Hasher; } });
Object.defineProperty(exports, "scopedHmacHasher", { enumerable: true, get: function () { return hashers_1.scopedHmacHasher; } });
Object.defineProperty(exports, "timingSafeEqualHex", { enumerable: true, get: function () { return hashers_1.timingSafeEqualHex; } });
var requireScope_1 = require("./express/api-key/requireScope");
Object.defineProperty(exports, "requireScope", { enumerable: true, get: function () { return requireScope_1.requireScope; } });
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
var buildAuditEvent_1 = require("./core/audit/buildAuditEvent");
Object.defineProperty(exports, "buildAuditEvent", { enumerable: true, get: function () { return buildAuditEvent_1.buildAuditEvent; } });
var ConsoleAuditSink_1 = require("./core/audit/ConsoleAuditSink");
Object.defineProperty(exports, "ConsoleAuditSink", { enumerable: true, get: function () { return ConsoleAuditSink_1.ConsoleAuditSink; } });
var hooks_1 = require("./core/audit/hooks");
Object.defineProperty(exports, "auditFailureHook", { enumerable: true, get: function () { return hooks_1.auditFailureHook; } });
Object.defineProperty(exports, "auditRateLimitHook", { enumerable: true, get: function () { return hooks_1.auditRateLimitHook; } });
Object.defineProperty(exports, "auditDeniedHook", { enumerable: true, get: function () { return hooks_1.auditDeniedHook; } });
// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
