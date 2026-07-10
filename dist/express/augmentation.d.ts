import type { SecurityContext } from '../core/context';
declare global {
    namespace Express {
        interface Request {
            /**
             * Populated by upstream auth middleware. Optional because unauthenticated
             * requests (and requests that ran before auth middleware) will not have it.
             */
            securityContext?: SecurityContext;
            /**
             * Raw received request body bytes, captured by an express.json `verify`
             * hook. The signing verifier prefers this over re-serialized `req.body`
             * so the hashed bytes match exactly what the client signed.
             */
            rawBody?: string | Buffer;
        }
    }
}
export {};
