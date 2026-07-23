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
  ipKeyResolved as ipKeyResolvedCore,
  verifiedIdentityKey as verifiedIdentityKeyCore,
  verifiedIdentityKeyResolved as verifiedIdentityKeyResolvedCore,
  decodedJwtKey as decodedJwtKeyCore,
  hmacBodyFieldKey as hmacBodyFieldKeyCore,
} from './core/rate-limit/keyGenerator';
import type {
  KeyGeneratorCore,
  DecodedJwtKeyOptionsCore,
  HmacBodyFieldKeyOptionsCore,
  ClientIpResolutionOptions,
} from './core/rate-limit/keyGenerator';
/** Express-pinned alias: same shape as the pre-carve `DecodedJwtKeyOptions`. */
export type DecodedJwtKeyOptions = DecodedJwtKeyOptionsCore<Request>;
export const ipKey: KeyGeneratorCore<Request> = ipKeyCore;
export const verifiedIdentityKey: KeyGeneratorCore<Request> = verifiedIdentityKeyCore;
export const defaultKeyGenerator: KeyGeneratorCore<Request> = defaultKeyGeneratorCore;
export const decodedJwtKey: (opts?: DecodedJwtKeyOptions) => KeyGeneratorCore<Request> =
  decodedJwtKeyCore;
/** Express-pinned alias: same shape as `HmacBodyFieldKeyOptionsCore<Request>`. */
export type HmacBodyFieldKeyOptions = HmacBodyFieldKeyOptionsCore<Request>;
export const hmacBodyFieldKey: (opts: HmacBodyFieldKeyOptions) => KeyGeneratorCore<Request> =
  hmacBodyFieldKeyCore;
export type { ClientIpResolutionOptions };
export const ipKeyResolved: (
  options?: ClientIpResolutionOptions,
) => KeyGeneratorCore<Request> = ipKeyResolvedCore;
export const verifiedIdentityKeyResolved: (
  options?: ClientIpResolutionOptions,
) => KeyGeneratorCore<Request> = verifiedIdentityKeyResolvedCore;

// Client-IP resolution (ROG-1094): framework-agnostic, so it's a safe direct
// re-export (no Request-pinning wrapper needed) — same reasoning as
// `resolveCorsPolicy`/`normalizeOrigin` below.
export { resolveClientIp } from './core/ip/resolveClientIp';

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
  RawApiKeyAuthenticator,
  RawApiKeyAuthentication,
  ApiKeyStaticKey,
  ApiKeyFailureReason,
  ApiKeyAuthLogger,
  ApiKeyErrorResponse,
} from './core/api-key/types';
export type {
  ScopePredicate,
  RequireScopeOptions,
  RequireScopeLogger,
} from './express/api-key/requireScope';

export { normalizeIp } from './core/api-key/normalizeIp';

// API-key ISSUANCE (mint/parse/mask/rotate). Framework-agnostic — no Request
// pinning needed, unlike verifyApiKey/createApiKeyAuth above.
export {
  generateApiKey,
  parseApiKey,
  maskApiKey,
  rotateApiKey,
  createThrottledTouchLastUsed,
} from './core/api-key/issuance';
export type {
  ApiKeyMaterial,
  GenerateApiKeyOptions,
  ParsedApiKey,
  ApiKeyStore,
  ApiKeyStoreRecord,
  ApiKeyInsertInput,
  ThrottledTouchLastUsedOptions,
} from './core/api-key/issuance';

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

// ---------------------------------------------------------------------------
// Phase 2 (v1.2.0) modules, also re-exported from root as of v1.2.1 for
// consistency with the other Express middleware above. Purely additive: the
// `./webhook`, `./express/webhook`, `./cors`, and `./express/cors` subpaths
// are unchanged.

// Webhook signature verification. `verifyWebhookSignature` is already
// framework-agnostic (it takes a plain `WebhookHeaders` record, not
// `Request`) and `createWebhookVerifier` is already Express-only, so both are
// safe direct re-exports here — no Request-pinning wrapper needed.
export { verifyWebhookSignature } from './core/webhook/verify';
export type {
  WebhookHeaders,
  HeaderReader,
  ReplayIdFromVerifiedBody,
  ReplayConfig,
  HmacSha256Config,
  Ed25519TimestampConfig,
  Ed25519Config,
  WebhookVerifyConfig,
  WebhookVerifyInput,
  WebhookVerifyReason,
  WebhookVerifyOutcome,
  PublicKeyResolver,
} from './core/webhook/verify';
// Renamed on export: the root already exports a `SecretResolver` type (above,
// from `./express/signing/createRequestSigningVerifier` — resolves a
// request-signing secret as `(req, ctx) => ...`). The webhook module's
// `SecretResolver` has a different shape, `(headers: HeaderReader) => ...`,
// so it is aliased here to avoid colliding with the existing export.
export type { SecretResolver as WebhookSecretResolver } from './core/webhook/verify';

export { createWebhookVerifier } from './express/webhook/createWebhookVerifier';
export type {
  WebhookVerifierLogger,
  WebhookVerifierExpressConfig,
  WebhookVerifierConfig,
} from './express/webhook/createWebhookVerifier';

// CORS origin-resolution policy. Framework-agnostic — no `cors`/express
// dependency — so it's a safe direct re-export.
export { resolveCorsPolicy, normalizeOrigin } from './core/cors/policy';
export type { CorsPolicyConfig, CorsPolicy, CorsRejectHook } from './core/cors/policy';

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

// Log redaction: already framework-agnostic (operate on plain strings/
// objects, not `Request`), so both are safe direct re-exports — no
// Request-pinning wrapper needed, same reasoning as `resolveClientIp` above.
export { redactUrl } from './core/redact/redactUrl';
export type { RedactUrlOptions } from './core/redact/redactUrl';
export { redactFields } from './core/redact/redactFields';
export type { RedactFieldsOptions } from './core/redact/redactFields';

// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
