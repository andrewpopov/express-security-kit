import type { Request, RequestHandler } from 'express';
import type { SecurityContext } from '../../core/context';
import type { SigningFailureReason, SigningLogger } from '../../core/signing/verifyRequestSignature';
import type { NonceStore } from '../../core/signing/nonceStore';
export type { SigningFailureReason, SigningLogger };
export interface SigningHeaderNames {
    timestamp: string;
    nonce: string;
    signature: string;
}
export type SecretResolver = (req: Request, ctx: SecurityContext | undefined) => string | undefined | Promise<string | undefined>;
export interface RequestSigningVerifierConfig {
    /**
     * Static shared secret, or a resolver. The resolver typically returns the
     * per-key secret from `ctx.hmacSecret` (populated by the api-key verifier),
     * or undefined when no secret is available → FAIL CLOSED.
     */
    secret: string | SecretResolver;
    /** Max clock skew in seconds. Default 300; clamped to [30, 900]. */
    maxSkewSeconds?: number;
    /** Header names. Defaults: x-timestamp / x-nonce / x-signature. */
    headerNames?: Partial<SigningHeaderNames>;
    /** Nonce format. Default /^[A-Za-z0-9:_-]{8,128}$/. */
    nonceFormat?: RegExp;
    /**
     * Replay-protection store (required). Read FRESH on every request (via an
     * accessor passed to the core), not captured once at construction — so
     * replacing `config.nonceStore` after this middleware is built (store
     * rotation/recovery) takes effect on the very next request, matching the
     * pre-carve middleware's behaviour. Mutate this property on the SAME
     * config object passed in here for the late binding to be observed.
     */
    nonceStore: NonceStore;
    /**
     * Replay scope key. Default: `ctx.keyId ?? ctx.principalId ?? 'global'`.
     * Keeps one key's nonces from colliding with another's.
     */
    nonceScope?: (req: Request, ctx: SecurityContext | undefined) => string;
    /** Body-string extractor. Default: rawBody-first (see module docs). */
    bodySource?: (req: Request) => string;
    /**
     * When true, FAIL CLOSED (reason `'no_raw_body'`) for body-bearing methods
     * (never GET/HEAD, which have no body) if `req.rawBody` is absent — instead
     * of silently falling back to `JSON.stringify(req.body)`, which can produce
     * bytes that differ from what the client actually signed (see the module
     * docs' rawBody warning). Only governs the DEFAULT body extractor; a custom
     * `bodySource` participates as provided and is not affected. Default false.
     */
    requireRawBody?: boolean;
    /** Audit hook; receives the specific reason. May be async. MUST NOT respond. */
    onFailure?: (req: Request, reason: SigningFailureReason) => void | Promise<unknown>;
    /** Injectable clock (ms). Default Date.now. */
    now?: () => number;
    /** Logger for hook rejections / store errors. Default console. */
    logger?: SigningLogger;
}
/**
 * OPT-IN HMAC request-signing + replay-protection middleware. FAIL-CLOSED: any
 * failure — unresolved secret, bad/absent timestamp/nonce/signature, replay, or
 * an unavailable nonce store — yields a GENERIC 401 and the request does NOT
 * proceed. The specific reason goes only to `onFailure`.
 *
 * This is a THIN adapter over {@link createRequestSignatureVerifierCore}: all
 * decision logic (ordering, fail-closed semantics, the nonce-consumed-after-
 * signature-proven rule) lives in the framework-agnostic core. This module
 * only does Express-specific extraction — reading headers, resolving the body
 * source, resolving the secret, deriving the nonce scope, and the
 * `requireRawBody` bodyless/custom-extractor exemption — and translates the
 * core's outcome into a response (`onFailure` + generic 401, or `next()`).
 */
export declare function createRequestSigningVerifier(config: RequestSigningVerifierConfig): RequestHandler;
