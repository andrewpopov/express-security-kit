"use strict";
// Framework-agnostic surface. Explicit shorthand named re-exports (no
// `export *`) so cjs-module-lexer statically detects the named exports for
// ESM consumers of the CommonJS build. NO file reachable from here may import
// 'express' or 'fastify' (enforced by scripts/check-core-agnostic.mjs).
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryNonceStore = exports.sha256Hex = exports.signRequest = exports.buildCanonicalString = exports.redactFields = exports.redactUrl = exports.scheduleRefundOnFinish = exports.createRateLimitCore = exports.hmacBodyFieldKey = exports.decodedJwtKey = exports.verifiedIdentityKey = exports.ipKey = exports.defaultKeyGenerator = exports.MemoryRateLimitStore = exports.auditDeniedHook = exports.auditRateLimitHook = exports.auditFailureHook = exports.ConsoleAuditSink = exports.buildAuditEvent = exports.AuditBuffer = exports.createThrottledTouchLastUsed = exports.rotateApiKey = exports.maskApiKey = exports.parseApiKey = exports.generateApiKey = exports.createCanonicalRawAuthenticator = exports.normalizeIp = exports.describeApiKeyConfigError = exports.buildDefaultContext = exports.extractRawKey = exports.verifyApiKey = exports.timingSafeEqualHex = exports.scopedHmacHasher = exports.sha256Hasher = void 0;
var hashers_1 = require("./api-key/hashers");
Object.defineProperty(exports, "sha256Hasher", { enumerable: true, get: function () { return hashers_1.sha256Hasher; } });
Object.defineProperty(exports, "scopedHmacHasher", { enumerable: true, get: function () { return hashers_1.scopedHmacHasher; } });
Object.defineProperty(exports, "timingSafeEqualHex", { enumerable: true, get: function () { return hashers_1.timingSafeEqualHex; } });
var verifyApiKey_1 = require("./api-key/verifyApiKey");
Object.defineProperty(exports, "verifyApiKey", { enumerable: true, get: function () { return verifyApiKey_1.verifyApiKey; } });
Object.defineProperty(exports, "extractRawKey", { enumerable: true, get: function () { return verifyApiKey_1.extractRawKey; } });
Object.defineProperty(exports, "buildDefaultContext", { enumerable: true, get: function () { return verifyApiKey_1.buildDefaultContext; } });
Object.defineProperty(exports, "describeApiKeyConfigError", { enumerable: true, get: function () { return verifyApiKey_1.describeApiKeyConfigError; } });
var normalizeIp_1 = require("./api-key/normalizeIp");
Object.defineProperty(exports, "normalizeIp", { enumerable: true, get: function () { return normalizeIp_1.normalizeIp; } });
var canonicalAuthenticator_1 = require("./api-key/canonicalAuthenticator");
Object.defineProperty(exports, "createCanonicalRawAuthenticator", { enumerable: true, get: function () { return canonicalAuthenticator_1.createCanonicalRawAuthenticator; } });
var issuance_1 = require("./api-key/issuance");
Object.defineProperty(exports, "generateApiKey", { enumerable: true, get: function () { return issuance_1.generateApiKey; } });
Object.defineProperty(exports, "parseApiKey", { enumerable: true, get: function () { return issuance_1.parseApiKey; } });
Object.defineProperty(exports, "maskApiKey", { enumerable: true, get: function () { return issuance_1.maskApiKey; } });
Object.defineProperty(exports, "rotateApiKey", { enumerable: true, get: function () { return issuance_1.rotateApiKey; } });
Object.defineProperty(exports, "createThrottledTouchLastUsed", { enumerable: true, get: function () { return issuance_1.createThrottledTouchLastUsed; } });
var AuditBuffer_1 = require("./audit/AuditBuffer");
Object.defineProperty(exports, "AuditBuffer", { enumerable: true, get: function () { return AuditBuffer_1.AuditBuffer; } });
var buildAuditEvent_1 = require("./audit/buildAuditEvent");
Object.defineProperty(exports, "buildAuditEvent", { enumerable: true, get: function () { return buildAuditEvent_1.buildAuditEvent; } });
var ConsoleAuditSink_1 = require("./audit/ConsoleAuditSink");
Object.defineProperty(exports, "ConsoleAuditSink", { enumerable: true, get: function () { return ConsoleAuditSink_1.ConsoleAuditSink; } });
var hooks_1 = require("./audit/hooks");
Object.defineProperty(exports, "auditFailureHook", { enumerable: true, get: function () { return hooks_1.auditFailureHook; } });
Object.defineProperty(exports, "auditRateLimitHook", { enumerable: true, get: function () { return hooks_1.auditRateLimitHook; } });
Object.defineProperty(exports, "auditDeniedHook", { enumerable: true, get: function () { return hooks_1.auditDeniedHook; } });
var store_1 = require("./rate-limit/store");
Object.defineProperty(exports, "MemoryRateLimitStore", { enumerable: true, get: function () { return store_1.MemoryRateLimitStore; } });
var keyGenerator_1 = require("./rate-limit/keyGenerator");
Object.defineProperty(exports, "defaultKeyGenerator", { enumerable: true, get: function () { return keyGenerator_1.defaultKeyGenerator; } });
Object.defineProperty(exports, "ipKey", { enumerable: true, get: function () { return keyGenerator_1.ipKey; } });
Object.defineProperty(exports, "verifiedIdentityKey", { enumerable: true, get: function () { return keyGenerator_1.verifiedIdentityKey; } });
Object.defineProperty(exports, "decodedJwtKey", { enumerable: true, get: function () { return keyGenerator_1.decodedJwtKey; } });
Object.defineProperty(exports, "hmacBodyFieldKey", { enumerable: true, get: function () { return keyGenerator_1.hmacBodyFieldKey; } });
var limiter_1 = require("./rate-limit/limiter");
Object.defineProperty(exports, "createRateLimitCore", { enumerable: true, get: function () { return limiter_1.createRateLimitCore; } });
Object.defineProperty(exports, "scheduleRefundOnFinish", { enumerable: true, get: function () { return limiter_1.scheduleRefundOnFinish; } });
var redactUrl_1 = require("./redact/redactUrl");
Object.defineProperty(exports, "redactUrl", { enumerable: true, get: function () { return redactUrl_1.redactUrl; } });
var redactFields_1 = require("./redact/redactFields");
Object.defineProperty(exports, "redactFields", { enumerable: true, get: function () { return redactFields_1.redactFields; } });
var signRequest_1 = require("./signing/signRequest");
Object.defineProperty(exports, "buildCanonicalString", { enumerable: true, get: function () { return signRequest_1.buildCanonicalString; } });
Object.defineProperty(exports, "signRequest", { enumerable: true, get: function () { return signRequest_1.signRequest; } });
Object.defineProperty(exports, "sha256Hex", { enumerable: true, get: function () { return signRequest_1.sha256Hex; } });
var nonceStore_1 = require("./signing/nonceStore");
Object.defineProperty(exports, "MemoryNonceStore", { enumerable: true, get: function () { return nonceStore_1.MemoryNonceStore; } });
// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so this entry never
// references ioredis.
