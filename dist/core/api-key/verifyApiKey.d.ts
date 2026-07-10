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
    /** 403 for `ip_denied`; 401 for everything else. */
    status: 401 | 403;
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
 * Verify an API key against the request, returning a discriminated outcome
 * WITHOUT sending HTTP or mutating the request. This is the shared verification
 * core (extract → prefix → static-key → hash+lookup → hash re-compare → expiry
 * → IP allowlist → build context) used by {@link createApiKeyAuth} and by
 * services that own their own response handling (e.g. a unified api-key-or-JWT
 * flow).
 *
 * NEVER throws: an unexpected error (e.g. a throwing `lookup`) resolves to
 * `{ ok: false, reason: 'error', present: true, status: 401 }` — fail closed.
 * It ignores the middleware-only config fields (`optional`, `onFailure`,
 * `logger`) and does NOT call `onFailure`; it DOES run `onAuthenticated`.
 */
export declare function verifyApiKey<Req extends SecurityRequest = SecurityRequest>(config: ApiKeyAuthConfigCore<Req>, req: Req): Promise<ApiKeyVerifyOutcome>;
export {};
