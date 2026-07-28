// Fastify adapter surface. Side-effect import: merges the `securityContext`/
// `rawBody` fields onto the ambient `FastifyRequest` type. MUST be a value
// import (not `import type`) so the augmentation is actually loaded by
// consumers of this subpath — mirrors how the root entry loads
// `./express/augmentation`.
import './augmentation';

// Explicit shorthand named re-exports (no `export *`) so cjs-module-lexer
// statically detects the named exports for ESM consumers of the CommonJS
// build — same discipline as `src/core/index.ts`.

export { createApiKeyAuth } from './api-key/createApiKeyAuth';
export type { FastifyApiKeyAuthConfig } from './api-key/createApiKeyAuth';

export { corsOptions } from './cors/corsOptions';
export type { CorsOptionsConfig, FastifyCorsOptions } from './cors/corsOptions';
