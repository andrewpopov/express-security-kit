"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRateLimiter = createRateLimiter;
const limiter_1 = require("../../core/rate-limit/limiter");
/**
 * Create a Fastify rate-limit `preHandler`.
 *
 * Pass a single config, or an ARRAY of tier configs applied in sequence — the
 * first tier to exceed its limit rejects the request (this is what enables the
 * recommended layered pattern: a coarse per-IP flood tier + a per-principal
 * fair-share tier). Each tier is independent; give tiers distinct stores/keys.
 *
 * This is deliberately mounted as a **`preHandler`**, not an `onRequest` hook
 * — the same lifecycle stage the Fastify api-key adapter uses. `hmacBodyFieldKey`
 * keys on a request-body field, and in Fastify the body is only parsed by the
 * time `preHandler` runs; an `onRequest` limiter would silently fall back to
 * IP keying for that strategy.
 *
 * No decision logic lives here — every number, header value, and body comes
 * from {@link createRateLimitCore}. This function only translates a
 * `RateLimitOutcome` into `reply` calls: it sets headers, sends the 429, and
 * (for `skipSuccessful`) hooks `reply.raw` via {@link scheduleRefundOnFinish}.
 * A tier that rejects `await reply.code(...).send(...)`s and returns straight
 * out of the loop — awaiting the send inside the `preHandler`'s promise chain
 * halts the lifecycle, so the route handler is never reached, the same
 * mechanism the api-key adapter relies on. There is no need to consult
 * `reply.sent` the way the Express adapter checks `res.headersSent`: the
 * Express adapter dispatches tiers through `next()` callbacks and has no other
 * way to know a tier already responded, but here the loop is owned directly.
 *
 * The DECISION and the BOOK-KEEPING fail OPEN: a tier that cannot reach a
 * decision (an unexpected throw from `evaluate()`, which already fails open
 * internally) is skipped, and a throwing header/refund-hook call on the ALLOW
 * path is logged via the same `safeWarn` path the core and Express adapter
 * use, with the request proceeding to the route handler. Once a tier has
 * DECIDED to reject, that is no longer true: writing the rejection (headers +
 * the 429 send) is NOT wrapped in a fail-open catch, so a failure there
 * propagates to Fastify's error handler (a 500) instead of silently letting
 * an over-limit request reach the route. A rate limiter must never take the
 * service down, but failing to WRITE a rejection must never become
 * permission to RUN the route either.
 */
function createRateLimiter(config) {
    const configs = Array.isArray(config) ? config : [config];
    const tiers = configs.map((tierConfig) => ({
        config: tierConfig,
        core: (0, limiter_1.createRateLimitCore)(tierConfig),
        refundFlag: Symbol('express-security-kit.rateLimitRefund'),
    }));
    return async (request, reply) => {
        for (const tier of tiers) {
            let outcome;
            try {
                outcome = await tier.core.evaluate(request);
            }
            catch (err) {
                // `evaluate` already fails open internally; this is belt-and-braces
                // for the decision phase only. A tier that cannot reach a decision is
                // skipped, exactly as a store outage is.
                (0, limiter_1.safeWarn)(tier.config, '[express-security-kit/fastify] rate-limit unexpected error; failing open', err);
                continue;
            }
            if (outcome.type === 'skip') {
                continue;
            }
            if (outcome.type === 'reject') {
                // DELIBERATELY NOT wrapped in a fail-open catch. Once the limiter has
                // DECIDED to reject, a failure to write that rejection must not
                // become permission to run the route. A throw here propagates to
                // Fastify's error handler (a 500) — the correct fail-CLOSED outcome
                // for a request that is genuinely over its limit.
                for (const [name, value] of outcome.headers) {
                    reply.header(name, value);
                }
                // `JSON.stringify` is safe here without a guard: the core has
                // already proven the body serializable (`resolveResponseBody` runs
                // `JSON.stringify` as a validity check and falls back to the default
                // envelope on failure), and the body is never nullish (a nullish
                // custom body is replaced by the default) — so do not "helpfully"
                // wrap this in a try/catch. Setting the content type explicitly and
                // sending the pre-stringified bytes matches Express's `res.json`
                // byte-for-byte for every JSON-serializable value, not just objects:
                // `reply.send(outcome.body)` alone would send a string/number/array
                // body as `text/plain`, diverging from Express. Fastify does not
                // re-serialize a string payload once the content type is already
                // `application/json`, so this sends exactly the stringified bytes.
                await reply
                    .type('application/json; charset=utf-8')
                    .code(outcome.status)
                    .send(JSON.stringify(outcome.body));
                return;
            }
            // Allowed. Header emission and the refund hook are BOOK-KEEPING, not
            // the security decision, so a failure in either fails OPEN — the
            // request is already authorized to proceed.
            try {
                for (const [name, value] of outcome.headers) {
                    reply.header(name, value);
                }
                if (outcome.onSettled) {
                    (0, limiter_1.scheduleRefundOnFinish)(reply.raw, outcome.onSettled, tier.refundFlag, (err) => (0, limiter_1.safeWarn)(tier.config, '[express-security-kit/fastify] could not hook response for refund', err));
                }
            }
            catch (err) {
                (0, limiter_1.safeWarn)(tier.config, '[express-security-kit/fastify] rate-limit unexpected error; failing open', err);
            }
        }
    };
}
