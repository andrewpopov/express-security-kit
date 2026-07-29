"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRateLimiter = exports.corsOptions = exports.createApiKeyAuth = void 0;
// Fastify adapter surface. Side-effect import: merges the `securityContext`/
// `rawBody` fields onto the ambient `FastifyRequest` type. MUST be a value
// import (not `import type`) so the augmentation is actually loaded by
// consumers of this subpath — mirrors how the root entry loads
// `./express/augmentation`.
require("./augmentation");
// Explicit shorthand named re-exports (no `export *`) so cjs-module-lexer
// statically detects the named exports for ESM consumers of the CommonJS
// build — same discipline as `src/core/index.ts`.
var createApiKeyAuth_1 = require("./api-key/createApiKeyAuth");
Object.defineProperty(exports, "createApiKeyAuth", { enumerable: true, get: function () { return createApiKeyAuth_1.createApiKeyAuth; } });
var corsOptions_1 = require("./cors/corsOptions");
Object.defineProperty(exports, "corsOptions", { enumerable: true, get: function () { return corsOptions_1.corsOptions; } });
var createRateLimiter_1 = require("./rate-limit/createRateLimiter");
Object.defineProperty(exports, "createRateLimiter", { enumerable: true, get: function () { return createRateLimiter_1.createRateLimiter; } });
