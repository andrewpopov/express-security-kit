import type { CorsOptions } from 'cors';
import type { CorsPolicyConfig } from '../../core/cors/policy';
/**
 * `corsOptions()` config: the core origin-resolution config PLUS overridable
 * NON-security defaults for the `cors` package's HTTP option surface
 * (methods/headers/credentials/maxAge/optionsSuccessStatus).
 *
 * Deliberately NOT a generic `overrides: CorsOptions` escape hatch (contrast
 * `createHelmetMiddleware`'s `overrides`) — a raw pass-through object could
 * contain `origin` and let a consumer replace the security-critical callback.
 * Only these explicitly named, non-security fields are overridable.
 */
export interface CorsOptionsConfig extends CorsPolicyConfig {
    /** @default true */
    credentials?: boolean;
    /** @default ['GET','POST','PUT','DELETE','PATCH','OPTIONS'] */
    methods?: string | string[];
    /** @default see module source — includes the kit's signed-request headers */
    allowedHeaders?: string | string[];
    /** @default ['RateLimit-Limit','RateLimit-Remaining','RateLimit-Reset'] */
    exposedHeaders?: string | string[];
    /** @default 200 */
    optionsSuccessStatus?: number;
    /** @default 86400 (24h) */
    maxAge?: number;
}
/**
 * Build `cors` package options from the kit's fail-closed origin policy.
 *
 * The core policy is resolved ONCE here, at construction — so a
 * production-empty allowlist throws at BOOT (fail closed), not on the first
 * request. The `origin` callback is fixed by this module and always calls
 * `callback(null, true | false)`; it never reflects the incoming origin
 * string and is not part of {@link CorsOptionsConfig}, so no consumer
 * override can replace it. Every other option is an overridable, purely
 * non-security default (methods/headers/credentials/maxAge/status).
 */
export declare function corsOptions(config: CorsOptionsConfig): CorsOptions;
