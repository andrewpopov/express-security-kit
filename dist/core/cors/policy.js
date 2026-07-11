"use strict";
/**
 * Framework-agnostic CORS origin-resolution policy. Per the design's scope
 * split, this module does ORIGIN RESOLUTION ONLY — allow/deny + prod-empty
 * fail-closed + normalization + dev overlays + no-Origin decision + the
 * rejection hook. It never touches HTTP methods/headers/maxAge; those are the
 * express adapter's job (`../../express/cors/corsOptions`) so this file stays
 * importable by any framework (or none) with zero `cors`/express dependency.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeOrigin = normalizeOrigin;
exports.resolveCorsPolicy = resolveCorsPolicy;
/**
 * Canonicalize a single configured or incoming origin value.
 * - Trims whitespace; an empty result is treated as absent (returns `null`,
 *   silently dropped by callers that build an allowlist from a list/CSV).
 * - The literal string `"null"` (the opaque origin browsers send for
 *   sandboxed iframes / `file:` / `data:` documents) is preserved as-is — it
 *   is not a parseable URL, but it IS a valid Origin header value.
 * - Otherwise, canonicalizes via `new URL(value).origin`, which strips any
 *   path/query/hash/credentials, lowercases scheme+host, and drops default
 *   ports (`:443` for https, `:80` for http).
 * - Throws on a non-empty value that is not a valid URL — callers building a
 *   CONFIGURED allowlist let this propagate (fail closed at construction: a
 *   typo'd origin must never be silently dropped). Callers normalizing an
 *   INCOMING request origin catch this and treat it as "does not match".
 */
function normalizeOrigin(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return null;
    }
    if (trimmed === 'null') {
        return 'null';
    }
    return new URL(trimmed).origin;
}
function addNormalized(set, raw) {
    const normalized = normalizeOrigin(raw);
    if (normalized) {
        set.add(normalized);
    }
}
function addCsv(set, csv) {
    if (!csv) {
        return;
    }
    for (const part of csv.split(',')) {
        addNormalized(set, part);
    }
}
function resolveCorsPolicy(config) {
    const isProd = config.env === 'production';
    const allowNoOrigin = config.allowNoOrigin ?? true;
    const onReject = config.onReject;
    const set = new Set();
    if (!isProd) {
        for (const origin of config.devDefaults ?? []) {
            addNormalized(set, origin);
        }
    }
    for (const origin of config.origins ?? []) {
        addNormalized(set, origin);
    }
    addCsv(set, config.originsCsv);
    if (isProd && set.size === 0) {
        // Fail closed: production must never fall back to a default or '*'.
        throw new Error('resolveCorsPolicy: no CORS origins configured for production ' +
            '(set `origins` and/or `originsCsv`) — refusing to start with an ' +
            'empty allowlist');
    }
    const origins = Object.freeze(Array.from(set));
    function safeOnReject(origin) {
        if (!onReject) {
            return;
        }
        try {
            onReject(origin);
        }
        catch {
            // A rejection-audit hook must never turn a normal deny into an error.
        }
    }
    function normalizeIncoming(origin) {
        try {
            return normalizeOrigin(origin);
        }
        catch {
            return null;
        }
    }
    return {
        origins,
        allowNoOrigin,
        allow(origin) {
            if (origin === undefined) {
                return allowNoOrigin;
            }
            const normalized = normalizeIncoming(origin);
            if (normalized !== null && set.has(normalized)) {
                return true;
            }
            safeOnReject(origin);
            return false;
        },
        resolveAllowedOrigin(origin) {
            if (origin === undefined) {
                return allowNoOrigin;
            }
            const normalized = normalizeIncoming(origin);
            if (normalized !== null && set.has(normalized)) {
                // `normalized` IS the canonical form: normalization is deterministic,
                // so the incoming origin's canonicalized value is byte-identical to
                // the allowlist entry it matched — never the raw, attacker-supplied
                // input (which may differ in path/case/port/scheme formatting).
                return normalized;
            }
            safeOnReject(origin);
            return false;
        },
    };
}
