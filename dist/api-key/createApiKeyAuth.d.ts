import type { RequestHandler } from 'express';
import { ApiKeyAuthConfig } from './types';
/**
 * Build an API-key authentication middleware.
 *
 * Auth FAILS CLOSED: any failure (missing/bad/expired/denied key, or an
 * unexpected error such as a throwing `lookup`) yields a GENERIC 401/403 and the
 * request does NOT proceed. This is the opposite of the rate limiter, which
 * fails open. Only the `onFailure` audit hook receives the specific reason.
 */
export declare function createApiKeyAuth(config: ApiKeyAuthConfig): RequestHandler;
