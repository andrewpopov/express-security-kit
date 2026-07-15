"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractRawKey = extractRawKey;
exports.buildDefaultContext = buildDefaultContext;
exports.verifyApiKey = verifyApiKey;
const hashers_1 = require("./hashers");
const normalizeIp_1 = require("./normalizeIp");
/**
 * Extract the raw presented key from the request.
 * - 'authorization' header: parsed as `Bearer <key>`.
 * - any other header: the raw trimmed value.
 */
function extractRawKey(req, headerName) {
    const raw = req.headers?.[headerName.toLowerCase()];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value !== 'string')
        return { kind: 'absent' };
    const trimmed = value.trim();
    if (trimmed.length === 0)
        return { kind: 'absent' };
    if (headerName.toLowerCase() === 'authorization') {
        const match = /^Bearer\s+(.+)$/i.exec(trimmed);
        if (!match)
            return { kind: 'malformed' };
        const token = match[1].trim();
        return token.length > 0
            ? { kind: 'key', key: token }
            : { kind: 'malformed' };
    }
    return { kind: 'key', key: trimmed };
}
function matchStaticKey(rawKey, staticKeys) {
    if (!staticKeys)
        return null;
    for (const staticKey of staticKeys) {
        // Constant-time full-string compare of raw secrets (these are not hashed).
        if ((0, hashers_1.timingSafeEqualHex)(rawKey, staticKey.value)) {
            return staticKey;
        }
    }
    return null;
}
function buildDefaultContext(record) {
    const context = {
        principalType: 'apiKey',
        principalId: record.id,
        keyId: record.id,
        scopes: record.scopes,
        rateLimitOverride: record.rateLimitOverride ?? undefined,
    };
    if (record.meta !== undefined)
        context.meta = record.meta;
    return context;
}
const failMissing = (reason, present, status = 401) => ({ ok: false, reason, present, status });
/** `config.errorStatus`, defaulting to 503. Never throws — a pathological
 * throwing getter falls back to the default rather than escaping the
 * fail-closed catch block that calls this. */
function resolveErrorStatus(config) {
    try {
        return typeof config.errorStatus === 'number' ? config.errorStatus : 503;
    }
    catch {
        return 503;
    }
}
/**
 * Verify an API key against the request, returning a discriminated outcome
 * WITHOUT sending HTTP or mutating the request. This is the shared verification
 * core (extract → prefix → static-key → hash+lookup → hash re-compare → expiry
 * → IP allowlist → build context) used by {@link createApiKeyAuth} and by
 * services that own their own response handling (e.g. a unified api-key-or-JWT
 * flow).
 *
 * NEVER throws: an unexpected error (e.g. a throwing `lookup` or `hasher`)
 * resolves to `{ ok: false, reason: 'error', present: true, status: 503 }`
 * (status configurable via `config.errorStatus`/`onError`) — fail closed,
 * but reported as an infrastructure failure, not a 401 authentication
 * failure.
 * It ignores the middleware-only config fields (`optional`, `onFailure`,
 * `logger`) and does NOT call `onFailure`; it DOES run `onAuthenticated`.
 */
async function verifyApiKey(config, req) {
    try {
        // Resolve config-derived values inside the try so the never-throws
        // guarantee holds even against a pathological throwing config getter.
        const headerName = config.headerName ?? 'authorization';
        const hasher = config.hasher ?? (0, hashers_1.sha256Hasher)();
        // 1. Extract the raw key.
        const extracted = extractRawKey(req, headerName);
        if (extracted.kind !== 'key') {
            // present=false only for a genuinely absent credential.
            return failMissing(extracted.kind === 'malformed' ? 'malformed' : 'missing', extracted.kind === 'malformed');
        }
        const rawKey = extracted.key;
        // 2. Prefix check (generic failure — do not reveal it was the prefix).
        if (!rawKey.startsWith(config.prefix)) {
            return failMissing('bad_prefix', true);
        }
        // 3. Static bootstrap/service keys (constant-time), checked before DB.
        const staticKey = matchStaticKey(rawKey, config.staticKeys);
        if (staticKey) {
            return {
                ok: true,
                record: null,
                context: {
                    principalType: 'service',
                    principalId: staticKey.principalId ?? staticKey.name,
                    keyId: staticKey.name,
                },
            };
        }
        // 4. Canonical host-owned raw authentication, or the legacy hash lookup.
        // The raw path is specifically for indexed public-id formats where only
        // the secret segment is hashed; never pre-hash the whole wire credential.
        let record;
        if (config.rawAuthenticator) {
            const authenticated = await config.rawAuthenticator(rawKey, req);
            if (!authenticated.ok)
                return failMissing(authenticated.reason ?? 'not_found', true);
            record = authenticated.record;
        }
        else {
            const computedHash = hasher(rawKey);
            record = await config.lookup(computedHash);
            if (!record)
                return failMissing('not_found', true);
            if (!record.hash || !(0, hashers_1.timingSafeEqualHex)(record.hash, computedHash)) {
                return failMissing('hash_mismatch', true);
            }
        }
        // 5. Expiry. A present-but-invalid Date (getTime() === NaN) is treated as
        //    expired — never trust a corrupt expiry to grant access.
        if (record.expiresAt) {
            const expiryTime = record.expiresAt.getTime();
            if (Number.isNaN(expiryTime) || expiryTime <= Date.now()) {
                return failMissing('expired', true);
            }
        }
        // 6. IP allowlist (403, not 401). Both sides are normalized (see
        //    normalizeIp) before comparing — otherwise a socket reporting an
        //    IPv4-mapped IPv6 address (`::ffff:203.0.113.7`, common behind some
        //    proxies/load balancers) would spuriously fail to match an allowlist
        //    entry of `203.0.113.7`. Still an EXACT match — no CIDR/range
        //    support. Its correctness depends entirely on a properly configured
        //    Express `trust proxy`; a too-broad trust proxy lets X-Forwarded-For
        //    spoofing defeat it. '*' disables the check; an undefined/malformed
        //    req.ip is denied unless '' is explicitly listed.
        if (record.allowedIps &&
            record.allowedIps.length > 0 &&
            !record.allowedIps.includes('*') &&
            !record.allowedIps.map(normalizeIp_1.normalizeIp).includes((0, normalizeIp_1.normalizeIp)(req.ip))) {
            return failMissing('ip_denied', true, 403);
        }
        // 7. Build the SecurityContext.
        const context = config.onAuthenticated
            ? await config.onAuthenticated(req, record)
            : buildDefaultContext(record);
        return { ok: true, context, record };
    }
    catch {
        // FAIL CLOSED on any unexpected error (e.g. a throwing lookup or
        // hasher). This is an INFRASTRUCTURE failure, not an authentication
        // failure — never an allow, but reported at `errorStatus` (default 503,
        // not 401) so it doesn't look like every key was revoked.
        return failMissing('error', true, resolveErrorStatus(config));
    }
}
