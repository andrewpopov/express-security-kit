export interface RedactUrlOptions {
    /** Query-param names whose VALUES are replaced (case-insensitive name match). Default: []. */
    sensitiveParams?: string[];
    /**
     * Redact the path segment IMMEDIATELY FOLLOWING any of these marker
     * segments (case-insensitive marker match). e.g. `afterSegments:
     * ['invites', 'invite']` redacts `<tok>` in `/api/invites/<tok>/setup`
     * and `/invite/<tok>`. Default: [].
     */
    sensitiveSegments?: {
        afterSegments: string[];
    };
    /** Replacement text. Default 'REDACTED'. */
    placeholder?: string;
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
export declare function redactUrl(url: string, options?: RedactUrlOptions): string;
