import './augmentation';
export { createApiKeyAuth } from './api-key/createApiKeyAuth';
export type { FastifyApiKeyAuthConfig } from './api-key/createApiKeyAuth';
export { corsOptions } from './cors/corsOptions';
export type { CorsOptionsConfig, FastifyCorsOptions } from './cors/corsOptions';
export { createRateLimiter } from './rate-limit/createRateLimiter';
export type { FastifyRateLimiterConfig, FastifyKeyGenerator, FastifyRateLimitRejection, } from './rate-limit/createRateLimiter';
