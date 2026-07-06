// Shorthand re-exports (no renaming) so cjs-module-lexer statically detects the
// named exports for ESM consumers of the CommonJS build.

export { createHelmetMiddleware } from './helmet/createHelmetMiddleware';
export type {
  HelmetPresetConfig,
  HelmetCspConfig,
} from './helmet/createHelmetMiddleware';

export { createRateLimiter } from './rate-limit/createRateLimiter';
export type {
  RateLimiterConfig,
  RateLimitAlgorithm,
  RateLimitOverride,
  RateLimiterLogger,
} from './rate-limit/createRateLimiter';

export { MemoryRateLimitStore } from './rate-limit/store';
export type {
  RateLimitStore,
  HitResult,
  MemoryRateLimitStoreOptions,
} from './rate-limit/store';

export {
  defaultKeyGenerator,
  ipKey,
  verifiedIdentityKey,
  decodedJwtKey,
} from './rate-limit/keyGenerator';
export type {
  KeyGenerator,
  DecodedJwtKeyOptions,
} from './rate-limit/keyGenerator';

export type { SecurityContext } from './types';

// Note: the Redis store is intentionally NOT exported here. Import it from the
// '@andrewpopov/express-security-kit/redis-store' subpath so the core entry
// never references ioredis.
