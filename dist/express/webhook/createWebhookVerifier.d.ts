import type { Request, RequestHandler } from 'express';
import type { WebhookVerifyConfig, WebhookVerifyReason } from '../../core/webhook/verify';
/** Minimal logger surface; defaults to console. */
export interface WebhookVerifierLogger {
    warn: (message: string, meta?: unknown) => void;
}
/**
 * Express-only additions layered on top of the framework-agnostic
 * {@link WebhookVerifyConfig} (HMAC-SHA256 or ed25519 — see `core/webhook/verify.ts`).
 */
export interface WebhookVerifierExpressConfig {
    /**
     * Extract the raw (unparsed) request body bytes to verify the signature
     * against. Defaults to reading `req.rawBody`.
     *
     * REQUIRES upstream raw-body capture — typically
     * `express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } })`
     * mounted before this middleware. Without that hook `req.rawBody` is
     * `undefined` and every request fails closed with `missing_body` (401):
     * express's body parsers discard the original bytes once parsed, so there
     * is no other reliable source for the exact bytes the sender signed.
     */
    rawBody?: (req: Request) => string | Buffer | undefined;
    /**
     * Audit hook invoked on EVERY verification failure with the specific
     * machine-readable reason. The HTTP response stays generic; the reason is
     * for your logs only. Never affects the auth decision: a throwing hook or a
     * rejected returned promise is caught/logged (never awaited) and does not
     * change the response or crash the request. MUST NOT send a response; the
     * middleware owns the 401/503.
     */
    onFailure?: (req: Request, reason: WebhookVerifyReason) => void | Promise<unknown>;
    /** Logger for onFailure hook rejections/throws. Default: console. */
    logger?: WebhookVerifierLogger;
}
/**
 * Config for {@link createWebhookVerifier}: the core `WebhookVerifyConfig`
 * discriminated union (`scheme: 'hmac-sha256' | 'ed25519'`) plus the express
 * bits above.
 */
export type WebhookVerifierConfig = WebhookVerifyConfig & WebhookVerifierExpressConfig;
/**
 * Build an inbound-webhook signature verification middleware, wrapping the
 * framework-agnostic {@link verifyWebhookSignature}.
 *
 * FAILS CLOSED: any verification failure — or an unexpected throw anywhere in
 * this middleware — yields a GENERIC response and the request does NOT
 * proceed. The specific {@link WebhookVerifyReason} is passed ONLY to
 * `onFailure`, never to the client, so the response never leaks whether a
 * secret/key exists or which check failed.
 */
export declare function createWebhookVerifier(config: WebhookVerifierConfig): RequestHandler;
