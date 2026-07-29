import type { CorsPolicyConfig } from '../../core/cors/policy';
/**
 * `corsOptions()` config: the core origin-resolution config PLUS overridable
 * NON-security defaults for `@fastify/cors`'s HTTP option surface
 * (methods/headers/credentials/maxAge/optionsSuccessStatus).
 *
 * Deliberately NOT a generic `overrides` escape hatch (contrast
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
 * The `allow` argument `@fastify/cors`'s origin callback accepts. Declared
 * here rather than imported from `@fastify/cors` (not a dependency of this
 * package) so `corsOptions()` never requires that plugin's types to resolve
 * — same discipline as the `fastify` `import type`s elsewhere in this
 * adapter: the return type must not force a consumer to install anything
 * beyond the `fastify` peer itself.
 */
type FastifyCorsAllow = boolean | string | RegExp | FastifyCorsAllow[];
/**
 * Minimal structural stand-in for `@fastify/cors`'s `FastifyCorsOptions`,
 * covering only the fields this module sets. `@fastify/cors` accepts
 * additional fields this type omits; that's fine, this is a subset used
 * purely to type the value this module returns.
 *
 * `origin` MUST mirror the plugin's own `OriginFunction` exactly — a property
 * (not a method) whose callback takes a REQUIRED second argument. Declaring
 * the callback's `allow` as optional, or `origin` as a method, makes the
 * returned object structurally incompatible with `FastifyCorsOptions`, and
 * `app.register(fastifyCors, corsOptions(...))` then fails to type-check in
 * every consumer with `No overload matches this call`. That is invisible
 * in-repo unless something actually registers the plugin, which is why the
 * integration test in `__tests__/corsOptions.integration.test.ts` — which
 * does exactly that — is what catches a regression here.
 */
export interface FastifyCorsOptions {
    credentials?: boolean;
    methods?: string | string[];
    allowedHeaders?: string | string[];
    exposedHeaders?: string | string[];
    optionsSuccessStatus?: number;
    maxAge?: number;
    origin: (origin: string | undefined, callback: (err: Error | null, allow: FastifyCorsAllow) => void) => void;
}
/**
 * Build `@fastify/cors` options from the kit's fail-closed origin policy.
 *
 * The core policy is resolved ONCE here, at construction — so a
 * production-empty allowlist throws at BOOT (fail closed), not on the first
 * request. The `origin` callback is fixed by this module and always calls
 * `callback(null, <canonical string> | boolean)`; it is not part of
 * {@link CorsOptionsConfig}, so no consumer override can replace it. Every
 * other option is an overridable, purely non-security default
 * (methods/headers/credentials/maxAge/status).
 *
 * IMPORTANT: for an allowed origin this calls back with the CANONICAL
 * allowlist string (via {@link CorsPolicy.resolveAllowedOrigin}), never
 * `true` and never the raw incoming `Origin` header. `callback(null, true)`
 * would make `@fastify/cors` REFLECT the raw request Origin verbatim into
 * `Access-Control-Allow-Origin` — since request headers are attacker-
 * controlled, that would echo back arbitrary bytes for any origin string
 * that merely *normalizes* to an allowed one, rather than emitting the fixed
 * value the allowlist actually authorizes.
 */
export declare function corsOptions(config: CorsOptionsConfig): FastifyCorsOptions;
export {};
