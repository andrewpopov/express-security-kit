import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { SecurityContext } from '../../core/context';

export type ScopePredicate = (
  ctx: SecurityContext | undefined,
  req: Request,
) => boolean;

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

const consoleLogger: RequireScopeLogger = {
  warn: (message, meta) => console.warn(message, meta ?? ''),
};

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
export function requireScope(
  predicate: ScopePredicate,
  opts: RequireScopeOptions = {},
): RequestHandler {
  const logger = opts.logger ?? consoleLogger;

  return (req: Request, res: Response, next: NextFunction) => {
    let result: unknown;
    try {
      result = predicate(req.securityContext, req);
    } catch {
      // A throwing policy predicate denies (fail closed).
      result = false;
    }

    // Guard against async-predicate misuse: a Promise is truthy but its real
    // value is unknown here. Treat it as a policy error and deny.
    if (result && typeof (result as Promise<unknown>).then === 'function') {
      logger.warn(
        '[express-security-kit] requireScope predicate returned a Promise; ' +
          'predicates MUST be synchronous. Denying.',
      );
      result = false;
    }

    // STRICT: only a literal `true` proceeds.
    if (result === true) {
      return next();
    }

    if (opts.onDenied) {
      try {
        const maybePromise = opts.onDenied(req) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as Promise<unknown>).then === 'function'
        ) {
          (maybePromise as Promise<unknown>).catch((err) =>
            logger.warn('[express-security-kit] onDenied hook rejected', err),
          );
        }
      } catch (err) {
        logger.warn('[express-security-kit] onDenied hook threw', err);
      }
    }
    return res.status(403).json({
      error: { code: 'FORBIDDEN', message: 'Forbidden' },
    });
  };
}
