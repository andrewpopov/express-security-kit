"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRateLimiter = createRateLimiter;
const store_1 = require("./store");
const keyGenerator_1 = require("./keyGenerator");
const consoleLogger = {
    warn: (message, meta) => console.warn(message, meta ?? ''),
};
/**
 * A shared default store so multiple limiters created without an explicit
 * `store` don't each spin up their own bucket map + timer. Tiers that must not
 * share state should pass their own store.
 */
let sharedMemoryStore;
function getSharedStore() {
    if (!sharedMemoryStore) {
        sharedMemoryStore = new store_1.MemoryRateLimitStore();
    }
    return sharedMemoryStore;
}
function resolveMax(config, req, override) {
    if (override) {
        return { windowMs: override.windowMs, max: override.max };
    }
    const max = typeof config.max === 'function' ? config.max(req) : config.max;
    return { windowMs: config.windowMs, max };
}
/**
 * Apply the algorithm to a store hit to produce a decision.
 *
 * fixed:   reject when current > max (current already includes this hit).
 * sliding: weighted = previous * (1 - elapsedInCurrent/windowMs) + current;
 *          reject when weighted >= max.
 */
function decide(algorithm, hit, windowMs, max, now) {
    if (algorithm === 'sliding') {
        const windowStart = hit.resetAt - windowMs;
        const elapsedInCurrent = Math.min(windowMs, Math.max(0, now - windowStart));
        const weightPrevious = Math.max(0, 1 - elapsedInCurrent / windowMs);
        const weighted = hit.previous * weightPrevious + hit.current;
        // `max` means the same thing across algorithms: allow up to and including
        // `max`, reject only when the weighted estimate EXCEEDS it. In an empty
        // window this lets exactly `max` through, matching the fixed window.
        const allowed = weighted <= max;
        const remaining = Math.max(0, Math.floor(max - weighted));
        return {
            allowed,
            limit: max,
            remaining,
            resetAt: hit.resetAt,
            used: weighted,
        };
    }
    // fixed
    const allowed = hit.current <= max;
    const remaining = Math.max(0, max - hit.current);
    return {
        allowed,
        limit: max,
        remaining,
        resetAt: hit.resetAt,
        used: hit.current,
    };
}
function applyHeaders(res, decision, now) {
    const resetSeconds = Math.max(0, Math.ceil((decision.resetAt - now) / 1000));
    res.setHeader('RateLimit-Limit', String(decision.limit));
    res.setHeader('RateLimit-Remaining', String(decision.remaining));
    res.setHeader('RateLimit-Reset', String(resetSeconds));
}
function rejectRequest(req, res, decision, key, config, emitHeaders, now) {
    const retryAfterSeconds = Math.max(0, Math.ceil((decision.resetAt - now) / 1000));
    if (emitHeaders) {
        applyHeaders(res, decision, now);
        res.setHeader('Retry-After', String(retryAfterSeconds));
    }
    // A misbehaving onLimit hook must NEVER convert a 429 into an allow. Catch a
    // synchronous throw, and attach a rejection handler to a returned promise so
    // an async hook can't produce an unhandled rejection.
    if (config.onLimit) {
        const logger = config.logger ?? consoleLogger;
        try {
            const maybePromise = config.onLimit(req, key);
            if (maybePromise &&
                typeof maybePromise.then === 'function') {
                maybePromise.catch((err) => logger.warn('[express-security-kit] onLimit hook rejected', err));
            }
        }
        catch (err) {
            logger.warn('[express-security-kit] onLimit hook threw', err);
        }
    }
    res.status(429).json({
        error: {
            code: 'RATE_LIMITED',
            message: 'Too many requests. Please retry later.',
            retryAfter: retryAfterSeconds,
        },
    });
}
function buildSingleLimiter(config) {
    const algorithm = config.algorithm ?? 'fixed';
    const keyGenerator = config.keyGenerator ?? keyGenerator_1.defaultKeyGenerator;
    const store = config.store ?? getSharedStore();
    const emitHeaders = config.headers ?? true;
    const logger = config.logger ?? consoleLogger;
    const clock = config.now ?? Date.now;
    const overrideResolver = config.overrideResolver ??
        ((req) => req.securityContext?.rateLimitOverride);
    return async (req, res, next) => {
        try {
            if (config.skip?.(req)) {
                return next();
            }
            const now = clock();
            const override = overrideResolver(req);
            const { windowMs, max } = resolveMax(config, req, override);
            const key = keyGenerator(req);
            let hit;
            try {
                hit = await store.hit(key, windowMs, now);
            }
            catch (err) {
                // Fail OPEN: never let a store outage take down the service.
                logger.warn('[express-security-kit] rate-limit store error; failing open', err);
                return next();
            }
            const decision = decide(algorithm, hit, windowMs, max, now);
            if (!decision.allowed) {
                return rejectRequest(req, res, decision, key, config, emitHeaders, now);
            }
            if (emitHeaders) {
                applyHeaders(res, decision, now);
            }
            return next();
        }
        catch (err) {
            // Any unexpected error also fails open.
            (config.logger ?? consoleLogger).warn('[express-security-kit] rate-limit unexpected error; failing open', err);
            return next();
        }
    };
}
/**
 * Create an Express rate-limit middleware.
 *
 * Pass a single config, or an ARRAY of tier configs applied in sequence — the
 * first tier to exceed its limit rejects the request (this is what enables the
 * recommended layered pattern: a coarse per-IP flood tier + a per-principal
 * fair-share tier). Each tier is independent; give tiers distinct stores/keys.
 */
function createRateLimiter(config) {
    if (Array.isArray(config)) {
        const tiers = config.map(buildSingleLimiter);
        return (req, res, next) => {
            let index = 0;
            const runNext = (err) => {
                if (err)
                    return next(err);
                // A tier that rejected has already sent the 429 response.
                if (res.headersSent)
                    return;
                const tier = tiers[index++];
                if (!tier)
                    return next();
                tier(req, res, runNext);
            };
            runNext();
        };
    }
    return buildSingleLimiter(config);
}
