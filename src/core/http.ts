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
  /**
   * The raw TCP socket this request arrived on. Optional because not every
   * caller (e.g. a hand-built test double) provides one, and `resolveClientIp`
   * must degrade gracefully when it's missing. Only `remoteAddress` is read —
   * the socket's peer address, which (unlike any header) cannot be forged by
   * the client, only by whatever actually opened the TCP connection. Used by
   * `resolveClientIp`'s `trustedPeers` peer-gate (ROG-1094 follow-up, ported
   * from fidash's `get_client_ip`) to decide whether forwarding headers are
   * even eligible for trust.
   */
  socket?: { remoteAddress?: string };
}
