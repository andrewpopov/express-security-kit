import type { SecurityContext } from '../core/context';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
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

// Ensure this file is treated as a module so the `declare global` augmentation
// merges into the ambient Express namespace instead of creating a local scope.
export {};
