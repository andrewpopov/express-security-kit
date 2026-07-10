import type { Request, RequestHandler } from 'express';
import type { SecurityContext } from '../../core/context';
export type ScopePredicate = (ctx: SecurityContext | undefined, req: Request) => boolean;
/** Minimal logger surface; defaults to console. */
export interface RequireScopeLogger {
    warn: (message: string, meta?: unknown) => void;
}
export interface RequireScopeOptions {
    /**
     * Called when access is denied, for audit. May be async — a returned
     * promise's rejection is caught and logged (never awaited). MUST NOT send a
     * response; the guard owns the 403.
     */
    onDenied?: (req: Request) => void | Promise<unknown>;
    /** Logger for predicate misuse / hook rejections. Default: console. */
    logger?: RequireScopeLogger;
}
/**
 * Guard-builder that runs a SERVICE-PROVIDED, SYNCHRONOUS predicate against
 * `req.securityContext`. It proceeds ONLY when the predicate returns the literal
 * boolean `true`; anything else denies with a generic 403:
 *  - `false` (or any non-`true` value, including a truthy object) → deny.
 *  - a thenable/Promise → MISUSE (predicates must be synchronous): denied and
 *    logged. Never `await`ed, so an async predicate can never let a request
 *    through on a truthy-Promise.
 *  - a thrown predicate → deny (fail closed).
 *
 * The kit ships only the mechanism — the predicate encodes the service's own
 * policy (stoki allowedActions, smarthome role gates, cairn org/project scope).
 * A predicate is responsible for handling an undefined context (e.g. requests
 * that ran the verifier in `optional` mode); returning false there denies.
 */
export declare function requireScope(predicate: ScopePredicate, opts?: RequireScopeOptions): RequestHandler;
