import type { Request, RequestHandler } from 'express';
import type { SecurityContext } from '../types';
import type { NonceStore } from './nonceStore';
/** Machine-readable failure reasons (passed to onFailure, never to the client). */
export type SigningFailureReason = 'no_secret' | 'timestamp' | 'skew' | 'nonce' | 'signature' | 'replay' | 'store_error' | 'error';
/** Minimal logger surface; defaults to console. */
export interface SigningLogger {
    warn: (message: string, meta?: unknown) => void;
}
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
    /** Replay-protection store (required). */
    nonceStore: NonceStore;
    /**
     * Replay scope key. Default: `ctx.keyId ?? ctx.principalId ?? 'global'`.
     * Keeps one key's nonces from colliding with another's.
     */
    nonceScope?: (req: Request, ctx: SecurityContext | undefined) => string;
    /** Body-string extractor. Default: rawBody-first (see module docs). */
    bodySource?: (req: Request) => string;
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
 * The signed nonce is consumed AFTER the signature is proven valid and BEFORE
 * `next()`, so an attacker cannot burn a victim's nonce with an unsigned/forged
 * request, and a valid signature can be used at most once within the skew TTL.
 */
export declare function createRequestSigningVerifier(config: RequestSigningVerifierConfig): RequestHandler;
