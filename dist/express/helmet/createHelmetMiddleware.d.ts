import { HelmetOptions } from 'helmet';
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
/**
 * Build a hardened helmet middleware. The CSP starts from a strict base
 * (default-src 'self'; object/frame 'none'; base-uri/form-action 'self') and
 * only widens where the caller supplies extra sources. `overrides` are applied
 * last and win over everything.
 */
export declare function createHelmetMiddleware(config?: HelmetPresetConfig): RequestHandler;
