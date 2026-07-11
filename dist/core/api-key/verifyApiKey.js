"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractRawKey = extractRawKey;
exports.buildDefaultContext = buildDefaultContext;
exports.verifyApiKey = verifyApiKey;
const hashers_1 = require("./hashers");
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
        // 4. Hash + DB lookup.
        const computedHash = hasher(rawKey);
        const record = await config.lookup(computedHash);
        if (!record) {
            return failMissing('not_found', true);
        }
        // 5. Defense in depth: constant-time compare the stored hash against the
        //    computed hash even though lookup was keyed by hash.
        if (!(0, hashers_1.timingSafeEqualHex)(record.hash, computedHash)) {
            return failMissing('hash_mismatch', true);
        }
        // 6. Expiry. A present-but-invalid Date (getTime() === NaN) is treated as
        //    expired — never trust a corrupt expiry to grant access.
        if (record.expiresAt) {
            const expiryTime = record.expiresAt.getTime();
            if (Number.isNaN(expiryTime) || expiryTime <= Date.now()) {
                return failMissing('expired', true);
            }
        }
        // 7. IP allowlist (403, not 401). NOTE: EXACT string match against req.ip —
        //    no CIDR/range support. Its correctness depends entirely on a properly
        //    configured Express `trust proxy`; a too-broad trust proxy lets
        //    X-Forwarded-For spoofing defeat it. '*' disables the check; an
        //    undefined req.ip is denied unless '' is explicitly listed.
        if (record.allowedIps &&
            record.allowedIps.length > 0 &&
            !record.allowedIps.includes('*') &&
            !record.allowedIps.includes(req.ip ?? '')) {
            return failMissing('ip_denied', true, 403);
        }
        // 8. Build the SecurityContext.
        const context = config.onAuthenticated
            ? await config.onAuthenticated(req, record)
            : buildDefaultContext(record);
        return { ok: true, context, record };
    }
    catch {
        // FAIL CLOSED on any unexpected error (e.g. lookup throws).
        return failMissing('error', true);
    }
}
