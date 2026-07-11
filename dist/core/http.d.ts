import type { IncomingHttpHeaders } from 'node:http';
import type { SecurityContext } from './context';
/**
 * Minimal request shape the framework-agnostic core reads. An Express
 * `Request` (and a Fastify `FastifyRequest`, in a later phase) structurally
 * satisfies this — `securityContext`/`rawBody` come from the Express
 * augmentation declared in `../express/augmentation.ts`.
 *
 * No file under `core/` may import `express` or `fastify` (enforced by
 * `scripts/check-core-agnostic.mjs`); core code is written entirely against
 * this interface instead.
 */
export interface SecurityRequest {
    headers: IncomingHttpHeaders;
    ip?: string;
    method?: string;
    originalUrl?: string;
    path?: string;
    securityContext?: SecurityContext;
    rawBody?: string | Buffer;
    body?: unknown;
}
