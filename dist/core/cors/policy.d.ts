/**
 * Framework-agnostic CORS origin-resolution policy. Per the design's scope
 * split, this module does ORIGIN RESOLUTION ONLY — allow/deny + prod-empty
 * fail-closed + normalization + dev overlays + no-Origin decision + the
 * rejection hook. It never touches HTTP methods/headers/maxAge; those are the
 * express adapter's job (`../../express/cors/corsOptions`) so this file stays
 * importable by any framework (or none) with zero `cors`/express dependency.
 */
/** A never-throw audit hook invoked when a non-undefined origin is denied. */
export type CorsRejectHook = (origin: string) => void;
export interface CorsPolicyConfig {
    /** Typically `process.env.NODE_ENV`. `'production'` triggers fail-closed mode. */
    env: string | undefined;
    /** Allowed origins, as full URLs or origins (e.g. `https://app.example.com`). */
    origins?: string[];
    /** Same as `origins`, but comma-separated (e.g. from an env var). */
    originsCsv?: string;
    /**
     * Origins merged in ONLY when `env !== 'production'` — e.g. localhost dev
     * servers. Ignored in production (fail-closed: prod never gets an implicit
     * default).
     */
    devDefaults?: string[];
    /**
     * Whether requests with no `Origin` header (curl, server-to-server calls —
     * not browser-guarded) pass. Default `true`.
     */
    allowNoOrigin?: boolean;
    /**
     * Audit hook called when a non-undefined origin is rejected. Wrapped so a
     * throwing hook can never turn a normal rejection into an unhandled error.
     */
    onReject?: CorsRejectHook;
}
export interface CorsPolicy {
    /**
     * `origin === undefined` → `allowNoOrigin`. Otherwise: normalize the
     * incoming origin and return `true` only on EXACT allowlist membership.
     * Never reflects the origin, never wildcards, never matches by
     * subdomain/suffix.
     */
    allow(origin: string | undefined): boolean;
    /**
     * `origin === undefined` → `allowNoOrigin` (the boolean). An allowed origin
     * → the CANONICAL, normalized allowlist string — i.e. the value stored in
     * `origins`, never the raw incoming value — so a caller that emits this
     * result verbatim (e.g. as an `Access-Control-Allow-Origin` header) never
     * reflects attacker-controlled bytes. A denied origin → `false`, and
     * `onReject` is still invoked exactly as `allow()` does.
     */
    resolveAllowedOrigin(origin: string | undefined): string | boolean;
    /** The resolved, normalized, de-duplicated allowlist. */
    origins: readonly string[];
    allowNoOrigin: boolean;
}
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
 * - Also throws when the parsed URL has an OPAQUE origin (`new URL(...).origin
 *   === 'null'` for schemes like `data:`, `file:`, `javascript:`, `blob:`
 *   without an inner http(s) URL, etc.) — WITHOUT this, a misconfigured
 *   `data:`/`file:` allowed-origin would silently collapse to the literal
 *   string `"null"` and authorize the shared `Origin: null` browsers send for
 *   every sandboxed-iframe/file:/data: context. The explicit literal `"null"`
 *   opt-in above is unaffected: this only rejects the SILENT collapse from a
 *   parsed opaque-origin URL, not a deliberate `"null"` string.
 */
export declare function normalizeOrigin(value: string): string | null;
export declare function resolveCorsPolicy(config: CorsPolicyConfig): CorsPolicy;
