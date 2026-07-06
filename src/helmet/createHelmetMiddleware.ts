import helmet, { HelmetOptions } from 'helmet';
import type { RequestHandler } from 'express';

/**
 * Extra CSP sources MERGED into the strict base. Each array lists additional
 * hosts/keywords appended to the corresponding directive — the base `'self'`
 * (and any base keywords) are always kept. You never REPLACE the base here;
 * use `overrides` for that.
 */
export interface HelmetCspConfig {
  scriptSrc?: string[];
  styleSrc?: string[];
  fontSrc?: string[];
  imgSrc?: string[];
  connectSrc?: string[];
  frameSrc?: string[];
  workerSrc?: string[];
}

export interface HelmetPresetConfig {
  /** Extra CSP sources merged into the strict base (see HelmetCspConfig). */
  csp?: HelmetCspConfig;
  /**
   * Add `'unsafe-inline'` to style-src. Needed by some component libraries that
   * inject inline `<style>`/style attributes. Default false. Never enables
   * inline SCRIPT — that stays blocked.
   */
  allowUnsafeInlineStyles?: boolean;
  /** HSTS max-age in seconds. Default 1 year. */
  hstsMaxAge?: number;
  /**
   * Raw helmet options deep-merged LAST, after the preset builds its config.
   * This is the escape hatch that always wins — including replacing whole CSP
   * directives.
   */
  overrides?: HelmetOptions;
}

const ONE_YEAR_SECONDS = 31_536_000;

type CspDirectives = Record<string, string[] | string | null>;

/** Append extras to a base directive, de-duplicating while preserving order. */
function extend(base: string[], extra?: string[]): string[] {
  if (!extra || extra.length === 0) return base;
  const seen = new Set(base);
  const merged = [...base];
  for (const value of extra) {
    if (!seen.has(value)) {
      seen.add(value);
      merged.push(value);
    }
  }
  return merged;
}

/**
 * Deep-merge helmet overrides onto the preset-built options. Plain objects are
 * merged recursively; arrays and primitives from `override` replace the base.
 * This lets `overrides.contentSecurityPolicy.directives.scriptSrc` fully
 * replace a directive while leaving untouched directives intact.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

function deepMerge<T>(base: T, override: unknown): T {
  if (override === undefined) return base;
  if (!isPlainObject(base) || !isPlainObject(override)) {
    return override as T;
  }
  const result: Record<string, unknown> = { ...base };
  for (const key of Object.keys(override)) {
    result[key] = deepMerge(
      (base as Record<string, unknown>)[key],
      override[key],
    );
  }
  return result as T;
}

/**
 * Build a hardened helmet middleware. The CSP starts from a strict base
 * (default-src 'self'; object/frame 'none'; base-uri/form-action 'self') and
 * only widens where the caller supplies extra sources. `overrides` are applied
 * last and win over everything.
 */
export function createHelmetMiddleware(
  config: HelmetPresetConfig = {},
): RequestHandler {
  const { csp = {}, allowUnsafeInlineStyles = false } = config;
  const hstsMaxAge = config.hstsMaxAge ?? ONE_YEAR_SECONDS;

  const styleBase = allowUnsafeInlineStyles
    ? ["'self'", "'unsafe-inline'"]
    : ["'self'"];

  const directives: CspDirectives = {
    defaultSrc: ["'self'"],
    scriptSrc: extend(["'self'"], csp.scriptSrc),
    styleSrc: extend(styleBase, csp.styleSrc),
    connectSrc: extend(["'self'"], csp.connectSrc),
    fontSrc: extend(["'self'"], csp.fontSrc),
    imgSrc: extend(["'self'", 'data:', 'https:'], csp.imgSrc),
    // object/frame stay locked to 'none' UNLESS the caller extends them.
    objectSrc: ["'none'"],
    frameSrc: csp.frameSrc && csp.frameSrc.length > 0 ? csp.frameSrc : ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
  };

  if (csp.workerSrc && csp.workerSrc.length > 0) {
    directives.workerSrc = extend(["'self'"], csp.workerSrc);
  }

  const presetOptions: HelmetOptions = {
    contentSecurityPolicy: {
      useDefaults: false,
      directives,
    },
    hsts: {
      maxAge: hstsMaxAge,
      includeSubDomains: true,
      preload: true,
    },
  };

  const merged = deepMerge(presetOptions, config.overrides);
  return helmet(merged);
}
