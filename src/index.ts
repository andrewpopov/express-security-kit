// Shorthand re-exports (no renaming) so cjs-module-lexer statically detects the
// named exports for ESM consumers of the CommonJS build.

export { createHelmetMiddleware } from './helmet/createHelmetMiddleware';
export type {
  HelmetPresetConfig,
  HelmetCspConfig,
} from './helmet/createHelmetMiddleware';

export { createRateLimiter } from './rate-limit/createRateLimiter';
export type {
  RateLimiterConfig,
  RateLimitAlgorithm,
  RateLimitOverride,
  RateLimiterLogger,
} from './rate-limit/createRateLimiter';

export { MemoryRateLimitStore } from './rate-limit/store';
export type {
  RateLimitStore,
  HitResult,
  MemoryRateLimitStoreOptions,
} from './rate-limit/store';

export {
  defaultKeyGenerator,
  ipKey,
  verifiedIdentityKey,
  decodedJwtKey,
} from './rate-limit/keyGenerator';
export type {
  KeyGenerator,
  DecodedJwtKeyOptions,
} from './rate-limit/keyGenerator';

export type { SecurityContext } from './types';

export { createApiKeyAuth } from './api-key/createApiKeyAuth';
export { verifyApiKey } from './api-key/verifyApiKey';
export type { ApiKeyVerifyOutcome } from './api-key/verifyApiKey';
export {
  sha256Hasher,
  scopedHmacHasher,
  timingSafeEqualHex,
} from './api-key/hashers';
export { requireScope } from './api-key/requireScope';
export type {
  ApiKeyRecord,
  KeyHasher,
  ApiKeyAuthConfig,
  ApiKeyStaticKey,
  ApiKeyFailureReason,
  ApiKeyAuthLogger,
} from './api-key/types';
export type {
  ScopePredicate,
  RequireScopeOptions,
  RequireScopeLogger,
} from './api-key/requireScope';

export {
  buildCanonicalString,
  signRequest,
  sha256Hex,
} from './signing/signRequest';
export type {
  CanonicalStringInput,
  SignRequestInput,
  SignedRequest,
} from './signing/signRequest';
export { createRequestSigningVerifier } from './signing/createRequestSigningVerifier';
export type {
  RequestSigningVerifierConfig,
  SigningFailureReason,
  SigningLogger,
  SigningHeaderNames,
  SecretResolver,
} from './signing/createRequestSigningVerifier';
export { MemoryNonceStore } from './signing/nonceStore';
export type {
  NonceStore,
  MemoryNonceStoreOptions,
} from './signing/nonceStore';

export { AuditBuffer } from './audit/AuditBuffer';
export { buildAuditEvent } from './audit/buildAuditEvent';
export { ConsoleAuditSink } from './audit/ConsoleAuditSink';
export {
  auditFailureHook,
  auditRateLimitHook,
  auditDeniedHook,
} from './audit/hooks';
export type {
  AuditEvent,
  AuditSink,
  AuditBufferConfig,
  AuditLogger,
} from './audit/types';
export type {
  BuildAuditEventInput,
  BuildAuditEventOptions,
} from './audit/buildAuditEvent';
export type { AuditHookOptions } from './audit/hooks';
export type { ConsoleAuditSinkLogger } from './audit/ConsoleAuditSink';

// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
