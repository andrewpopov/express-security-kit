// Side-effect import: merges the `securityContext`/`rawBody` fields onto the
// ambient `Express.Request` type. MUST be a value import (not `import type`)
// so the augmentation is actually loaded by root consumers.
import './express/augmentation';

// Shorthand re-exports (no renaming) so cjs-module-lexer statically detects the
// named exports for ESM consumers of the CommonJS build.

export { createHelmetMiddleware } from './express/helmet/createHelmetMiddleware';
export type {
  HelmetPresetConfig,
  HelmetCspConfig,
} from './express/helmet/createHelmetMiddleware';

export { createRateLimiter } from './express/rate-limit/createRateLimiter';
export type {
  RateLimiterConfig,
  RateLimitAlgorithm,
  RateLimitOverride,
  RateLimitRejection,
  RateLimiterLogger,
} from './express/rate-limit/createRateLimiter';
export type { KeyGenerator } from './express/rate-limit/createRateLimiter';

export { MemoryRateLimitStore } from './core/rate-limit/store';
export type {
  RateLimitStore,
  HitResult,
  MemoryRateLimitStoreOptions,
} from './core/rate-limit/store';

export {
  defaultKeyGenerator,
  ipKey,
  verifiedIdentityKey,
  decodedJwtKey,
} from './core/rate-limit/keyGenerator';
import type { Request } from 'express';
import type { DecodedJwtKeyOptionsCore } from './core/rate-limit/keyGenerator';
/** Express-pinned alias: same shape as the pre-carve `DecodedJwtKeyOptions`. */
export type DecodedJwtKeyOptions = DecodedJwtKeyOptionsCore<Request>;

export type { SecurityContext } from './core/context';

export { createApiKeyAuth } from './express/api-key/createApiKeyAuth';
export type { ApiKeyAuthConfig } from './express/api-key/createApiKeyAuth';
export { verifyApiKey } from './core/api-key/verifyApiKey';
export type { ApiKeyVerifyOutcome } from './core/api-key/verifyApiKey';
export {
  sha256Hasher,
  scopedHmacHasher,
  timingSafeEqualHex,
} from './core/api-key/hashers';
export { requireScope } from './express/api-key/requireScope';
export type {
  ApiKeyRecord,
  KeyHasher,
  ApiKeyStaticKey,
  ApiKeyFailureReason,
  ApiKeyAuthLogger,
} from './core/api-key/types';
export type {
  ScopePredicate,
  RequireScopeOptions,
  RequireScopeLogger,
} from './express/api-key/requireScope';

export {
  buildCanonicalString,
  signRequest,
  sha256Hex,
} from './core/signing/signRequest';
export type {
  CanonicalStringInput,
  SignRequestInput,
  SignedRequest,
} from './core/signing/signRequest';
export { createRequestSigningVerifier } from './express/signing/createRequestSigningVerifier';
export type {
  RequestSigningVerifierConfig,
  SigningFailureReason,
  SigningLogger,
  SigningHeaderNames,
  SecretResolver,
} from './express/signing/createRequestSigningVerifier';
export { MemoryNonceStore } from './core/signing/nonceStore';
export type {
  NonceStore,
  MemoryNonceStoreOptions,
} from './core/signing/nonceStore';

export { AuditBuffer } from './core/audit/AuditBuffer';
export { buildAuditEvent } from './core/audit/buildAuditEvent';
export { ConsoleAuditSink } from './core/audit/ConsoleAuditSink';
export {
  auditFailureHook,
  auditRateLimitHook,
  auditDeniedHook,
} from './core/audit/hooks';
export type {
  AuditEvent,
  AuditSink,
  AuditBufferConfig,
  AuditLogger,
} from './core/audit/types';
export type {
  BuildAuditEventInput,
  BuildAuditEventOptions,
} from './core/audit/buildAuditEvent';
export type { AuditHookOptions } from './core/audit/hooks';
export type { ConsoleAuditSinkLogger } from './core/audit/ConsoleAuditSink';

// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
