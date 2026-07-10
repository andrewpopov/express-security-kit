// Side-effect import: merges the `securityContext`/`rawBody` fields onto the
// ambient `Express.Request` type. MUST be a value import (not `import type`)
// so the augmentation is actually loaded by root consumers.
import './express/augmentation';

import type { Request } from 'express';

// Root re-exports pin the request type to express `Request` so the PUBLIC
// signatures — including type-level introspection via `Parameters<>` /
// `ReturnType<>` — match v1.0.0 exactly. The `./core` subpath keeps the generic
// `<Req extends SecurityRequest = SecurityRequest>` forms for framework-agnostic
// consumers. Values are re-exported through a pinned-type `const` binding, so the
// underlying function identity (and thus behavior) is unchanged.

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

// Key generators: pinned to express `Request` at the root (generic in ./core).
import {
  defaultKeyGenerator as defaultKeyGeneratorCore,
  ipKey as ipKeyCore,
  verifiedIdentityKey as verifiedIdentityKeyCore,
  decodedJwtKey as decodedJwtKeyCore,
} from './core/rate-limit/keyGenerator';
import type {
  KeyGeneratorCore,
  DecodedJwtKeyOptionsCore,
} from './core/rate-limit/keyGenerator';
/** Express-pinned alias: same shape as the pre-carve `DecodedJwtKeyOptions`. */
export type DecodedJwtKeyOptions = DecodedJwtKeyOptionsCore<Request>;
export const ipKey: KeyGeneratorCore<Request> = ipKeyCore;
export const verifiedIdentityKey: KeyGeneratorCore<Request> = verifiedIdentityKeyCore;
export const defaultKeyGenerator: KeyGeneratorCore<Request> = defaultKeyGeneratorCore;
export const decodedJwtKey: (opts?: DecodedJwtKeyOptions) => KeyGeneratorCore<Request> =
  decodedJwtKeyCore;

export type { SecurityContext } from './core/context';

export { createApiKeyAuth } from './express/api-key/createApiKeyAuth';
import type { ApiKeyAuthConfig } from './express/api-key/createApiKeyAuth';
export type { ApiKeyAuthConfig };

// verifyApiKey: pinned to `(config, req: Request)` — the v1.0.0 signature.
import { verifyApiKey as verifyApiKeyCore } from './core/api-key/verifyApiKey';
import type { ApiKeyVerifyOutcome } from './core/api-key/verifyApiKey';
export type { ApiKeyVerifyOutcome };
export const verifyApiKey: (
  config: ApiKeyAuthConfig,
  req: Request,
) => Promise<ApiKeyVerifyOutcome> = verifyApiKeyCore;

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
import { AuditBuffer as AuditBufferClass } from './core/audit/AuditBuffer';
export { ConsoleAuditSink } from './core/audit/ConsoleAuditSink';
export type {
  AuditEvent,
  AuditSink,
  AuditBufferConfig,
  AuditLogger,
} from './core/audit/types';
import type { AuditEvent } from './core/audit/types';

// buildAuditEvent + audit hooks: pinned to express `Request` at the root.
import { buildAuditEvent as buildAuditEventCore } from './core/audit/buildAuditEvent';
import type {
  BuildAuditEventInput,
  BuildAuditEventOptions,
} from './core/audit/buildAuditEvent';
export type {
  BuildAuditEventInput,
  BuildAuditEventOptions,
} from './core/audit/buildAuditEvent';
export const buildAuditEvent: (
  req: Request,
  input: BuildAuditEventInput,
  options?: BuildAuditEventOptions,
) => AuditEvent = buildAuditEventCore;

import {
  auditFailureHook as auditFailureHookCore,
  auditRateLimitHook as auditRateLimitHookCore,
  auditDeniedHook as auditDeniedHookCore,
} from './core/audit/hooks';
import type { AuditHookOptions } from './core/audit/hooks';
export type { AuditHookOptions } from './core/audit/hooks';
export const auditFailureHook: (
  buffer: AuditBufferClass,
  action: string,
  outcome?: AuditEvent['outcome'],
  options?: AuditHookOptions,
) => (req: Request, reason: string) => void = auditFailureHookCore;
export const auditRateLimitHook: (
  buffer: AuditBufferClass,
  action: string,
  options?: AuditHookOptions,
) => (req: Request, key: string) => void = auditRateLimitHookCore;
export const auditDeniedHook: (
  buffer: AuditBufferClass,
  action: string,
  options?: AuditHookOptions,
) => (req: Request) => void = auditDeniedHookCore;
export type { ConsoleAuditSinkLogger } from './core/audit/ConsoleAuditSink';

// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
