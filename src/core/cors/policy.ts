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
 */
export function normalizeOrigin(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed === 'null') {
    return 'null';
  }
  return new URL(trimmed).origin;
}

function addNormalized(set: Set<string>, raw: string): void {
  const normalized = normalizeOrigin(raw);
  if (normalized) {
    set.add(normalized);
  }
}

function addCsv(set: Set<string>, csv: string | undefined): void {
  if (!csv) {
    return;
  }
  for (const part of csv.split(',')) {
    addNormalized(set, part);
  }
}

export function resolveCorsPolicy(config: CorsPolicyConfig): CorsPolicy {
  const isProd = config.env === 'production';
  const allowNoOrigin = config.allowNoOrigin ?? true;
  const onReject = config.onReject;

  const set = new Set<string>();

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
    throw new Error(
      'resolveCorsPolicy: no CORS origins configured for production ' +
        '(set `origins` and/or `originsCsv`) — refusing to start with an ' +
        'empty allowlist',
    );
  }

  const origins = Object.freeze(Array.from(set));

  function safeOnReject(origin: string): void {
    if (!onReject) {
      return;
    }
    try {
      onReject(origin);
    } catch {
      // A rejection-audit hook must never turn a normal deny into an error.
    }
  }

  function normalizeIncoming(origin: string): string | null {
    try {
      return normalizeOrigin(origin);
    } catch {
      return null;
    }
  }

  return {
    origins,
    allowNoOrigin,
    allow(origin: string | undefined): boolean {
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
    resolveAllowedOrigin(origin: string | undefined): string | boolean {
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
