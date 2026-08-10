"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createCanonicalRawAuthenticator = createCanonicalRawAuthenticator;
const node_crypto_1 = require("node:crypto");
const issuance_1 = require("./issuance");
const hashers_1 = require("./hashers");
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
function createCanonicalRawAuthenticator(options) {
    const prefix = options.prefix;
    if (!prefix) {
        throw new Error('createCanonicalRawAuthenticator requires a non-empty prefix');
    }
    const findByKeyId = options.findByKeyId;
    const hasher = options.hasher ?? (0, hashers_1.sha256Hasher)();
    // Dummy stored-hash for the "unknown keyId" path (auth-kit's `dummyHash`
    // pattern, PKG-137). Computed ONCE per authenticator instance (never per
    // request) from bytes generated here — never derived from anything a
    // caller/attacker supplies (not the presented key, not the keyId). Route
    // it through the configured `hasher` so its shape/length matches what a
    // real stored hash for THIS authenticator looks like, but never let a
    // broken `hasher` crash construction over it: fall back to raw random hex.
    // Either way `hasher` still runs on every actual request below (against
    // the presented secret), so a `hasher` that only throws at request time is
    // still caught — identically — by both the known- and unknown-keyId paths.
    let dummyHash;
    try {
        dummyHash = hasher((0, node_crypto_1.randomBytes)(32).toString('base64url'));
    }
    catch {
        dummyHash = (0, node_crypto_1.randomBytes)(32).toString('hex');
    }
    return async (rawKey) => {
        // parseApiKey returns null for two different reasons that must NOT be
        // collapsed into the same report: a prefix mismatch (not this
        // authenticator's call to make — `bad_prefix` is reserved for
        // verifyApiKey's own upstream check, see the docstring above) and a
        // genuine STRUCTURAL failure (no '.' separator, or an empty
        // keyId/secret) once the prefix DOES match. Check the prefix first,
        // cheaply, so the two are distinguishable without re-implementing
        // parseApiKey's own parsing — parseApiKey remains the single source of
        // truth for what "parses" means; this only tells its `null` apart from
        // itself.
        if (!rawKey.startsWith(prefix)) {
            return { ok: false, reason: 'not_found' };
        }
        const parsed = (0, issuance_1.parseApiKey)(rawKey, prefix);
        if (!parsed) {
            return { ok: false, reason: 'malformed' };
        }
        let record;
        try {
            record = await findByKeyId(parsed.keyId);
        }
        catch {
            // Store/infra failure — NOT an auth failure. Fail closed via
            // 'unavailable' so verifyApiKey reports errorStatus (503 by default),
            // never a 401 that would make monitoring blind to the outage.
            return { ok: false, reason: 'unavailable' };
        }
        // Always hash the presented secret and constant-time-compare it — against
        // the REAL stored hash when the keyId is known, against the fixed dummy
        // hash when it isn't — so a known vs. unknown keyId does IDENTICAL work
        // and, if `hasher` throws, throws identically. This is what keeps
        // `findByKeyId` resolving null from being a timing/reason oracle for
        // key-ID existence (see the docstring above).
        let computedHash;
        try {
            computedHash = hasher(parsed.secret);
        }
        catch {
            // A throwing hasher is an infrastructure fault (same treatment as
            // findByKeyId throwing above) — never an auth failure, and critically,
            // the SAME reason regardless of whether the keyId was known.
            return { ok: false, reason: 'unavailable' };
        }
        const storedHash = record?.hash;
        const matches = (0, hashers_1.timingSafeEqualHex)(storedHash ?? dummyHash, computedHash);
        if (!record) {
            return { ok: false, reason: 'not_found' };
        }
        if (!storedHash || !matches) {
            return { ok: false, reason: 'hash_mismatch' };
        }
        return { ok: true, record };
    };
}
