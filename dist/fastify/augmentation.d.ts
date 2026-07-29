import type { SecurityContext } from '../core/context';
declare module 'fastify' {
    interface FastifyRequest {
        /**
         * Populated by upstream auth middleware. Optional because unauthenticated
         * requests (and requests that ran before auth middleware) will not have it.
         */
        securityContext?: SecurityContext;
        /**
         * Raw received request body bytes, captured by a body-parser `onRequest`/
         * `preValidation` hook. The signing verifier prefers this over
         * re-serialized `request.body` so the hashed bytes match exactly what the
         * client signed.
         */
        rawBody?: string | Buffer;
    }
}
export {};
