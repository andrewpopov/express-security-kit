import type { SecurityRequest } from '../http';
import type { ApiKeyRecord, KeyHasher, RawApiKeyAuthenticator } from './types';
/**
 * The record {@link CreateCanonicalRawAuthenticatorOptions.findByKeyId} must
 * return: an {@link ApiKeyRecord} whose `hash` is the hash of the SECRET
 * SEGMENT — exactly what {@link ../issuance.generateApiKey} stores, never a
 * hash of the whole wire credential.
 */
export type CanonicalApiKeyRecord = ApiKeyRecord & {
    hash: string;
};
export interface CreateCanonicalRawAuthenticatorOptions {
    /**
     * Required key prefix — the same value passed to {@link
     * ../issuance.generateApiKey} and to `ApiKeyAuthConfigCore.prefix`.
     */
    prefix: string;
    /**
     * Look up the stored record by the PUBLIC keyId — an indexed lookup, never
     * a table scan or a hash-recompute-and-compare loop over every stored key.
     * Return `null` when not found. A THROW is treated as an infrastructure
     * failure (`reason: 'unavailable'`), never an auth failure — verifyApiKey
     * maps it to `config.errorStatus` (default 503), never 401.
     */
    findByKeyId: (keyId: string) => Promise<CanonicalApiKeyRecord | null>;
    /**
     * Hasher applied to the SECRET SEGMENT only — must be the same hasher (and
     * same options, e.g. an HMAC scope) used to produce the hash `generateApiKey`
     * stored. Default: `sha256Hasher()`, matching `generateApiKey`'s own default.
     */
    hasher?: KeyHasher;
}
/**
 * Build the CANONICAL {@link RawApiKeyAuthenticator}: parse the presented
 * `<prefix><keyId>.<secret>` credential, look the record up by its PUBLIC
 * keyId (indexed, never a table scan), and constant-time compare the stored
 * hash against `hasher(secret)` — the hash of the SECRET SEGMENT alone,
 * exactly what {@link ../issuance.generateApiKey} stores.
 *
 * This is the adapter the README's "Verify (in your `lookup`): parse, look up
 * by the PUBLIC keyId..." recipe described but the API could not actually
 * express — `ApiKeyAuthConfigCore.lookup` receives only a computed hash, never
 * the raw key, so it has nothing to parse a keyId out of. Wire the returned
 * function into `ApiKeyAuthConfigCore.rawAuthenticator` instead:
 *
 * ```ts
 * createApiKeyAuth({
 *   prefix: 'app_',
 *   rawAuthenticator: createCanonicalRawAuthenticator({
 *     prefix: 'app_',
 *     findByKeyId: (keyId) => db.apiKey.findByKeyId(keyId),
 *   }),
 * });
 * ```
 *
 * Failure reasons (never 'error' — a store/hasher failure is reported as
 * 'unavailable', which `verifyApiKey` fails closed at `errorStatus`, default
 * 503, not as a 401):
 * - key doesn't match `prefix` → `not_found` (a `RawApiKeyAuthentication`
 *   cannot report `bad_prefix` — that reason is reserved for `verifyApiKey`'s
 *   own upstream prefix check, which runs BEFORE this authenticator is ever
 *   invoked in the normal `createApiKeyAuth` pipeline; a wrong-prefix key
 *   handed to this function directly, bypassing that pipeline, still gets the
 *   generic `not_found` rather than a reason this authenticator has no
 *   business claiming).
 * - prefix matches but the key is structurally unparseable (no `.` separator,
 *   or an empty keyId/secret on either side of it) → `malformed` (PKG-154).
 *   Distinct from unknown-keyId `not_found` below: `malformed` means the
 *   credential could never have been valid regardless of what's in the
 *   store — usually a client bug or a truncated secret — while `not_found`
 *   means it's well-formed but nobody issued it — usually revocation or
 *   probing. Same generic 401 either way; this only sharpens the
 *   machine-readable reason for monitoring/`onFailure`.
 * - unknown keyId (`findByKeyId` resolves `null`) → `not_found`, but ONLY
 *   after doing the same `hasher` + constant-time-compare work a known keyId
 *   would (against a fixed dummy hash — see below). An unknown keyId that
 *   short-circuited straight to `not_found` would be an existence oracle for
 *   key IDs: observable via timing, AND — more reliably — via `reason`: a
 *   throwing `hasher` would otherwise 401 (`not_found`) an unknown id but 503
 *   (`unavailable`) a known one, a clean probe with no timing measurement
 *   required. See PKG-149 Finding 1 follow-up / PKG-137's `dummyHash` in the
 *   sibling `auth-kit` package, same pattern.
 * - `findByKeyId` throws → `unavailable`
 * - `hasher` throws (on either a known or unknown keyId — same outcome
 *   either way, by construction) → `unavailable`. A broken hasher is an
 *   infrastructure/config fault, not an auth decision: it says nothing about
 *   whether the presented secret is right, so it must not be reported as
 *   `hash_mismatch` (a real auth failure) or allowed to leak into the
 *   existence oracle above by producing a different reason for known vs.
 *   unknown keyIds.
 * - stored hash doesn't match `hasher(secret)` → `hash_mismatch`
 */
export declare function createCanonicalRawAuthenticator<Req extends SecurityRequest = SecurityRequest>(options: CreateCanonicalRawAuthenticatorOptions): RawApiKeyAuthenticator<Req>;
