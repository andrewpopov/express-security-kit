"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redactFields = redactFields;
/**
 * Walk `value`, building a deep copy. `depth` starts at 1 for the value
 * passed to {@link redactFields} itself; object keys are only checked
 * against `fields` while `depth <= maxDepth` (arrays are depth-neutral —
 * passing through an array does not consume depth budget, so an
 * array-of-objects at the root is still treated as "top level"). `ancestors`
 * tracks the current call chain (not every object seen) so a cycle is
 * detected and broken without mistaking a shared, non-circular reference
 * (a DAG) for one.
 */
function walk(value, fields, placeholder, maxDepth, depth, ancestors) {
    if (value === null || typeof value !== 'object')
        return value;
    const obj = value;
    if (ancestors.has(obj))
        return undefined; // cycle guard: break the cycle
    if (Array.isArray(value)) {
        ancestors.add(obj);
        try {
            return value.map((item) => walk(item, fields, placeholder, maxDepth, depth, ancestors));
        }
        finally {
            ancestors.delete(obj);
        }
    }
    ancestors.add(obj);
    try {
        const checkKeys = depth <= maxDepth;
        const result = {};
        for (const key of Object.keys(value)) {
            const val = value[key];
            if (checkKeys && fields.has(key)) {
                result[key] = placeholder;
            }
            else {
                result[key] = walk(val, fields, placeholder, maxDepth, depth + 1, ancestors);
            }
        }
        return result;
    }
    finally {
        ancestors.delete(obj);
    }
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
function redactFields(value, options) {
    // Default constant, so even reading `options.placeholder` (a hostile getter,
    // or a null `options`) inside the guard can never defeat the never-throws /
    // fail-closed contract — the catch always has a safe placeholder to return.
    let placeholder = '[REDACTED]';
    try {
        placeholder = options.placeholder ?? placeholder;
        const fields = new Set(options.fields);
        const recurse = options.recurse ?? true;
        const maxDepth = recurse ? Infinity : 1;
        return walk(value, fields, placeholder, maxDepth, 1, new Set());
    }
    catch {
        // Fail closed: never return the unredacted original.
        return placeholder;
    }
}
