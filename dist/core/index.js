"use strict";
// Framework-agnostic surface. Explicit shorthand named re-exports (no
// `export *`) so cjs-module-lexer statically detects the named exports for
// ESM consumers of the CommonJS build. NO file reachable from here may import
// 'express' or 'fastify' (enforced by scripts/check-core-agnostic.mjs).
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryNonceStore = exports.sha256Hex = exports.signRequest = exports.buildCanonicalString = exports.decodedJwtKey = exports.verifiedIdentityKey = exports.ipKey = exports.defaultKeyGenerator = exports.MemoryRateLimitStore = exports.auditDeniedHook = exports.auditRateLimitHook = exports.auditFailureHook = exports.ConsoleAuditSink = exports.buildAuditEvent = exports.AuditBuffer = exports.buildDefaultContext = exports.extractRawKey = exports.verifyApiKey = exports.timingSafeEqualHex = exports.scopedHmacHasher = exports.sha256Hasher = void 0;
var hashers_1 = require("./api-key/hashers");
Object.defineProperty(exports, "sha256Hasher", { enumerable: true, get: function () { return hashers_1.sha256Hasher; } });
Object.defineProperty(exports, "scopedHmacHasher", { enumerable: true, get: function () { return hashers_1.scopedHmacHasher; } });
Object.defineProperty(exports, "timingSafeEqualHex", { enumerable: true, get: function () { return hashers_1.timingSafeEqualHex; } });
var verifyApiKey_1 = require("./api-key/verifyApiKey");
Object.defineProperty(exports, "verifyApiKey", { enumerable: true, get: function () { return verifyApiKey_1.verifyApiKey; } });
Object.defineProperty(exports, "extractRawKey", { enumerable: true, get: function () { return verifyApiKey_1.extractRawKey; } });
Object.defineProperty(exports, "buildDefaultContext", { enumerable: true, get: function () { return verifyApiKey_1.buildDefaultContext; } });
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
var signRequest_1 = require("./signing/signRequest");
Object.defineProperty(exports, "buildCanonicalString", { enumerable: true, get: function () { return signRequest_1.buildCanonicalString; } });
Object.defineProperty(exports, "signRequest", { enumerable: true, get: function () { return signRequest_1.signRequest; } });
Object.defineProperty(exports, "sha256Hex", { enumerable: true, get: function () { return signRequest_1.sha256Hex; } });
var nonceStore_1 = require("./signing/nonceStore");
Object.defineProperty(exports, "MemoryNonceStore", { enumerable: true, get: function () { return nonceStore_1.MemoryNonceStore; } });
// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so this entry never
// references ioredis.
