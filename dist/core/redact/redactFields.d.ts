export interface RedactFieldsOptions {
    /** Exact-case key names to redact. */
    fields: string[];
    /** Descend into nested objects & arrays. Default true. */
    recurse?: boolean;
    /** Replacement text. Default '[REDACTED]'. */
    placeholder?: string;
}
/**
 * Recursively redact object fields by exact-case key name, returning a DEEP
 * COPY — the input is never mutated. Cairn's audit body previously redacted
 * only top-level exact-match keys; this adds recursion into nested objects
 * and arrays, while `recurse: false` preserves that original top-level-only
 * behavior exactly. Exact-case (not case-insensitive) matching is
 * intentional, to preserve Cairn's current behavior unchanged.
 *
 * Non-object values (including `null`) pass through unchanged. Cyclic
 * references are detected and broken (the cyclic property is omitted)
 * rather than recursing forever.
 *
 * NEVER throws, and FAILS CLOSED: if the walk raises unexpectedly (e.g. a
 * hostile object with a throwing getter or `Object.keys` trap), it returns
 * the placeholder instead of the original value — a redactor must never emit
 * unredacted input on error, or it would leak exactly the secrets it exists
 * to strip. The realistic input (a parsed JSON request body) never triggers
 * this path; it is pure defense in depth.
 */
export declare function redactFields<T>(value: T, options: RedactFieldsOptions): T;
