import type { SecurityContext } from '../context';
import type { SecurityRequest } from '../http';
import { ApiKeyAuthConfigCore, ApiKeyFailureReason, ApiKeyRecord } from './types';
/**
 * Result of {@link verifyApiKey}. A discriminated union — the verifier reports
 * the decision WITHOUT touching `res` or `req.securityContext`, so a caller with
 * a unified/multi-method auth flow (try api-key, else JWT) can decide whether to
 * fall through or reject.
 */
export type ApiKeyVerifyOutcome = {
    ok: true;
    context: SecurityContext;
    record: ApiKeyRecord | null;
} | {
    ok: false;
    reason: ApiKeyFailureReason;
    /**
     * Whether a credential was actually presented. `false` ONLY when the
     * credential is genuinely ABSENT (no/empty header) — the case where a
     * caller may fall through to another auth method. `true` for a malformed
     * or otherwise-invalid presented key (a real failed attempt).
     */
    present: boolean;
    /**
     * 403 for `ip_denied`; `config.errorStatus` (default 503) for `error`
     * or `unavailable` (an infrastructure failure, not an auth failure);
     * 401 for everything else.
     */
    status: number;
};
/**
 * Outcome of extracting the presented credential:
 * - `absent`    — the header is not present or empty.
 * - `malformed` — the header IS present but cannot be parsed into a key (e.g.
 *   `Authorization: Basic x`, a bare `Bearer`). A FAILED auth attempt.
 * - `{ key }`   — a usable raw key.
 */
type ExtractResult = {
    kind: 'absent';
} | {
    kind: 'malformed';
} | {
    kind: 'key';
    key: string;
};
/**
 * Extract the raw presented key from the request.
 * - 'authorization' header: parsed as `Bearer <key>`.
 * - any other header: the raw trimmed value.
 */
export declare function extractRawKey<Req extends SecurityRequest = SecurityRequest>(req: Req, headerName: string): ExtractResult;
export declare function buildDefaultContext(record: ApiKeyRecord): SecurityContext;
/**
 * `ApiKeyAuthConfigCore` needs at least one of `rawAuthenticator` (canonical)
 * or `lookup` (legacy) — supplying NEITHER can't work under any code path, so
 * it is rejected: {@link createApiKeyAuth} (Express and Fastify) calls this
 * eagerly at construction and throws with this message; {@link verifyApiKey}
 * calls it per-request and — consistent with its documented never-throws
 * contract — folds an invalid config into the existing `reason: 'error'`
 * vocabulary instead of throwing. (Before this check existed, "neither"
 * already produced the same `reason: 'error'`/503 outcome via an uncaught
 * `TypeError` from calling `undefined` as `lookup`, swallowed by
 * `verifyApiKey`'s fail-closed catch-all — this makes that failure explicit
 * and, for `createApiKeyAuth`, immediate at construction instead of on the
 * first request.)
 *
 * Supplying BOTH is deliberately NOT an error here — see {@link
 * warnIfBothCredentialPathsConfigured}. `lookup` used to be REQUIRED, so
 * every canonical-path consumer was forced to supply a dead `lookup` just to
 * satisfy the type; rejecting "both" at construction would break every one of
 * them on upgrade, punishing them for a workaround the old type forced on
 * them. `rawAuthenticator` silently wins today, unchanged — the warning is
 * how the "both" case gets deprecated without breaking anyone on this release.
 *
 * Returns `null` when the config is valid.
 */
export declare function describeApiKeyConfigError<Req extends SecurityRequest>(config: Pick<ApiKeyAuthConfigCore<Req>, 'rawAuthenticator' | 'lookup'>): string | null;
/**
 * Warn, ONCE per config object, when both `rawAuthenticator` and `lookup`
 * are configured. Behavior is unchanged (`rawAuthenticator` wins, `lookup` is
 * silently ignored) — this is a deprecation notice, not an enforcement:
 * supplying both will become a construction-time error in the next major
 * version, so remove the now-unnecessary `lookup` ahead of that. Matches
 * `AuditBuffer`'s `safeWarn` shape: a broken/throwing logger must NEVER break
 * the caller, so the logger call is wrapped in try/catch.
 */
export declare function warnIfBothCredentialPathsConfigured<Req extends SecurityRequest>(config: Pick<ApiKeyAuthConfigCore<Req>, 'rawAuthenticator' | 'lookup' | 'logger'>): void;
/**
 * Verify an API key against the request, returning a discriminated outcome
 * WITHOUT sending HTTP or mutating the request. This is the shared verification
 * core (extract → prefix → static-key → hash+lookup → hash re-compare → expiry
 * → IP allowlist → build context) used by {@link createApiKeyAuth} and by
 * services that own their own response handling (e.g. a unified api-key-or-JWT
 * flow).
 *
 * NEVER throws: an unexpected error (e.g. a throwing `lookup` or `hasher`),
 * or a config missing BOTH of `rawAuthenticator`/`lookup` (see {@link
 * describeApiKeyConfigError}), resolves to `{ ok: false, reason: 'error',
 * present: true, status: 503 }` (status configurable via
 * `config.errorStatus`/`onError`) — fail closed, but reported as an
 * infrastructure failure, not a 401 authentication failure. A config
 * supplying BOTH does not error — `rawAuthenticator` wins, `lookup` is
 * ignored, and a one-time deprecation warning is logged (see {@link
 * warnIfBothCredentialPathsConfigured}).
 * It ignores the middleware-only config fields (`optional`, `onFailure`) and
 * does NOT call `onFailure`; it DOES run `onAuthenticated`, and it DOES use
 * `logger` for the "both configured" deprecation warning above.
 */
export declare function verifyApiKey<Req extends SecurityRequest = SecurityRequest>(config: ApiKeyAuthConfigCore<Req>, req: Req): Promise<ApiKeyVerifyOutcome>;
export {};
