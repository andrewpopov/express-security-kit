/**
 * Shared security context attached to a request by upstream auth middleware
 * (api-key verification, session auth, service-token auth — LATER phases).
 *
 * Phase 1 modules (helmet preset, rate limiter) only READ this: the rate
 * limiter's default key generator and override resolver consult it. It is
 * declared here so the whole kit shares one canonical shape and so downstream
 * services get the Express `Request.securityContext` augmentation for free
 * (see `../express/augmentation.ts`).
 */
export interface SecurityContext {
  /** How the principal was authenticated. `anonymous` = no verified identity. */
  principalType: 'apiKey' | 'user' | 'service' | 'anonymous';
  /** Stable identifier for the verified principal (user id, service name, ...). */
  principalId?: string;
  /** Identifier of the specific API key used, when principalType is 'apiKey'. */
  keyId?: string;
  /** Opaque scope/permission payload; shape owned by the consuming service. */
  scopes?: unknown;
  /** Per-principal rate-limit override consumed by the default overrideResolver. */
  rateLimitOverride?: { windowMs: number; max: number };
  /**
   * Per-key HMAC secret for request signing (Phase 3). Typically copied from the
   * authenticated ApiKeyRecord.hmacSecret by an `onAuthenticated` hook so the
   * signing verifier's secret resolver can read it off the context. Treat as
   * sensitive; it lives only in the in-memory request context.
   */
  hmacSecret?: string | null;
  /**
   * Free-form service-specific data carried on the context (e.g. an org id a
   * service stashed on its ApiKeyRecord). Populated from `ApiKeyRecord.meta` by
   * the default context builder.
   */
  meta?: Record<string, unknown>;
}
