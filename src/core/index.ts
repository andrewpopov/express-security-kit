// Framework-agnostic surface. Explicit shorthand named re-exports (no
// `export *`) so cjs-module-lexer statically detects the named exports for
// ESM consumers of the CommonJS build. NO file reachable from here may import
// 'express' or 'fastify' (enforced by scripts/check-core-agnostic.mjs).

export type { SecurityRequest } from './http';
export type { SecurityContext } from './context';

export {
  sha256Hasher,
  scopedHmacHasher,
  timingSafeEqualHex,
} from './api-key/hashers';
export { verifyApiKey, extractRawKey, buildDefaultContext } from './api-key/verifyApiKey';
export type { ApiKeyVerifyOutcome } from './api-key/verifyApiKey';
export type {
  ApiKeyRecord,
  KeyHasher,
  ApiKeyAuthConfigCore,
  ApiKeyStaticKey,
  ApiKeyFailureReason,
  ApiKeyAuthLogger,
  ApiKeyErrorResponse,
} from './api-key/types';
export { normalizeIp } from './api-key/normalizeIp';

export {
  generateApiKey,
  parseApiKey,
  maskApiKey,
  rotateApiKey,
  createThrottledTouchLastUsed,
} from './api-key/issuance';
export type {
  ApiKeyMaterial,
  GenerateApiKeyOptions,
  ParsedApiKey,
  ApiKeyStore,
  ApiKeyStoreRecord,
  ApiKeyInsertInput,
  ThrottledTouchLastUsedOptions,
} from './api-key/issuance';

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
  KeyGeneratorCore,
  DecodedJwtKeyOptionsCore,
} from './rate-limit/keyGenerator';

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
export { MemoryNonceStore } from './signing/nonceStore';
export type {
  NonceStore,
  MemoryNonceStoreOptions,
} from './signing/nonceStore';

// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so this entry never
// references ioredis.
