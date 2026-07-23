"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redactUrl = redactUrl;
/** Split `str` on the FIRST occurrence of `sep`. Right side is `undefined` when `sep` is absent. */
function splitOnce(str, sep) {
    const idx = str.indexOf(sep);
    if (idx === -1)
        return [str, undefined];
    return [str.slice(0, idx), str.slice(idx + sep.length)];
}
/**
 * Percent-decode a token for COMPARISON only (never for output). A URL author
 * can spell a sensitive name/marker in encoded form (`%74oken`, `%69nvites`)
 * that a downstream decoder still routes as `token`/`invites`; comparing the
 * raw bytes would let that slip past redaction. `+` is left as-is (it's a
 * query-value space convention, not part of a name we key on). Malformed
 * escapes throw in `decodeURIComponent` — fall back to the raw token so a bad
 * escape never breaks the caller (and the raw form still gets its normal
 * exact-match chance).
 */
function decodeForCompare(token) {
    try {
        return decodeURIComponent(token);
    }
    catch {
        return token;
    }
}
/** Redact the value of any `key=value` pair whose (decoded) key case-insensitively matches `sensitiveLower`. */
function redactQuery(query, sensitiveLower, placeholder) {
    if (sensitiveLower.size === 0 || query.length === 0)
        return query;
    return query
        .split('&')
        .map((pair) => {
        const [key] = splitOnce(pair, '=');
        if (!sensitiveLower.has(decodeForCompare(key).toLowerCase()))
            return pair;
        return `${key}=${placeholder}`;
    })
        .join('&');
}
/** Redact the segment immediately following any segment whose (decoded) form matches `markersLower`. */
function redactPath(path, markersLower, placeholder) {
    if (markersLower.size === 0)
        return path;
    const segments = path.split('/');
    for (let i = 0; i < segments.length - 1; i++) {
        if (markersLower.has(decodeForCompare(segments[i]).toLowerCase())) {
            segments[i + 1] = placeholder;
        }
    }
    return segments.join('/');
}
/**
 * Redact `user:pass@` / `user@` userinfo from an absolute URL's authority.
 * `req.originalUrl` never carries userinfo, but the helper tolerates absolute
 * URLs and those can embed credentials — a stated part of "strip URL
 * credentials". Only touches the authority between `scheme://` and the first
 * `/ ? #`; a bare path (no `scheme://`) is returned untouched.
 */
function redactUserInfo(url, placeholder) {
    const schemeMatch = /^([a-z][a-z0-9+.-]*:\/\/)/i.exec(url);
    if (!schemeMatch)
        return url;
    const afterScheme = schemeMatch[1].length;
    const authorityEnd = url.slice(afterScheme).search(/[/?#]/);
    const authority = authorityEnd === -1 ? url.slice(afterScheme) : url.slice(afterScheme, afterScheme + authorityEnd);
    const at = authority.lastIndexOf('@');
    if (at === -1)
        return url;
    const rest = authorityEnd === -1 ? '' : url.slice(afterScheme + authorityEnd);
    return `${schemeMatch[1]}${placeholder}@${authority.slice(at + 1)}${rest}`;
}
function doRedact(url, options) {
    const placeholder = options.placeholder ?? 'REDACTED';
    const sensitiveLower = new Set((options.sensitiveParams ?? []).map((p) => p.toLowerCase()));
    const markersLower = new Set((options.sensitiveSegments?.afterSegments ?? []).map((s) => s.toLowerCase()));
    const [withoutFragment, fragment] = splitOnce(url, '#');
    const [pathAndAuthority, query] = splitOnce(withoutFragment, '?');
    const withoutUserInfo = redactUserInfo(pathAndAuthority, placeholder);
    const redactedPath = redactPath(withoutUserInfo, markersLower, placeholder);
    const redactedQuery = query !== undefined ? redactQuery(query, sensitiveLower, placeholder) : undefined;
    return (redactedPath +
        (redactedQuery !== undefined ? `?${redactedQuery}` : '') +
        (fragment !== undefined ? `#${fragment}` : ''));
}
/**
 * Strip credentials (query-string secrets and path tokens) out of a URL or
 * path before it reaches a log sink. Typically called with `req.originalUrl`
 * (a relative path with optional query, e.g.
 * `/api/invites/abc/setup?token=xyz&foo=1`), but also tolerates a bare path
 * with no query or an absolute URL — the leading slash, path structure,
 * remaining query params (and their order), and any `#fragment` are all
 * preserved untouched.
 *
 * NEVER throws — malformed input returns a best-effort safe string,
 * preferring over-redaction to leaking.
 */
function redactUrl(url, options = {}) {
    const placeholder = options.placeholder ?? 'REDACTED';
    try {
        if (typeof url !== 'string')
            return placeholder;
        return doRedact(url, options);
    }
    catch {
        // Defense in depth: this must never throw, even on hostile input.
        return placeholder;
    }
}
