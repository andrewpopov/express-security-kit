import type { NonceStore } from './nonceStore';
/**
 * Machine-readable failure reasons for request-signature verification (an
 * adapter passes these to its own `onFailure`/audit hook — NEVER to the
 * client). This is decision vocabulary, not an HTTP concern, so it lives here
 * rather than in any one adapter; the Express adapter re-exports it so
 * existing imports keep working.
 */
export type SigningFailureReason = 'no_secret' | 'timestamp' | 'skew' | 'nonce' | 'signature' | 'replay' | 'store_error' | 'no_raw_body' | 'error';
/** Minimal logger surface; defaults to console. */
export interface SigningLogger {
    warn: (message: string, meta?: unknown) => void;
}
export interface RequestSignatureVerifierConfigCore {
    /** Max clock skew in seconds. Default 300; clamped to [30, 900]. */
    maxSkewSeconds?: number;
    /** Nonce format. Default /^[A-Za-z0-9:_-]{8,128}$/. */
    nonceFormat?: RegExp;
    /**
     * Replay-protection store (required), or a zero-argument accessor that
     * returns it. Resolved FRESH on every `verify()` call rather than once at
     * construction: the pre-carve middleware read `config.nonceStore` off the
     * host's config object on every request, so a host that rotated/replaced
     * the store after building the middleware (store recovery, credential
     * rotation) saw the new store take effect immediately. Accepting a plain
     * `NonceStore` still works (and is captured once, same as before) — only a
     * caller that wants late binding needs to pass the accessor form.
     */
    nonceStore: NonceStore | (() => NonceStore);
    /**
     * When true, FAIL CLOSED (reason `'no_raw_body'`) whenever the caller
     * reports `input.hasRawBody: false`. What "has raw body" means for a given
     * request — the bodyless GET/HEAD exemption, whether a custom body
     * extractor is in play — is entirely the CALLER's job to resolve before
     * calling `verify`; the core only enforces the policy against whatever the
     * caller reports. Default false.
     */
    requireRawBody?: boolean;
    /** Injectable clock (ms). Default Date.now. */
    now?: () => number;
    /** Logger for store errors / unexpected failures. Default console. */
    logger?: SigningLogger;
}
/**
 * Plain facts the core needs to verify one request's signature. Every
 * framework-specific extraction — reading headers, resolving the body
 * source, resolving the secret, deriving the nonce scope — is the CALLER's
 * job; this carries only already-resolved values (or zero-argument
 * accessors for them), never a framework request object.
 *
 * `secret`, `body`, `nonceScope`, and `hasRawBody` are zero-argument
 * functions rather than pre-computed values ON PURPOSE: the pre-carve
 * middleware evaluated each of these LAZILY, at a specific point in its
 * control flow, so that a request failing an earlier check never triggered a
 * later one's side effects (e.g. an unresolved secret short-circuited before
 * a custom `bodySource` or `nonceScope` ever ran). `verify()` calls each
 * accessor at the exact point the original code evaluated it — see the
 * ordering comments inline below. `timestampHeader` / `nonceHeader` /
 * `signatureHeader`, `method`, and `url` stay eager: reading a header has no
 * side effects, so there is nothing to defer.
 */
export interface RequestSignatureVerifyInput {
    /** HTTP method (case-insensitive; upper-cased for the canonical string). */
    method: string;
    /** Request target exactly as received (path + query), e.g. req.originalUrl. */
    url: string;
    /** Raw timestamp header value, if present. */
    timestampHeader: string | undefined;
    /** Raw nonce header value, if present. */
    nonceHeader: string | undefined;
    /** Raw signature header value, if present. */
    signatureHeader: string | undefined;
    /**
     * Exact bytes to hash into the canonical string. Ignored for GET/HEAD.
     * Called ONLY after the `requireRawBody` precondition passes — a
     * `bodySource` with side effects (or one that can throw, e.g. on a
     * circular object) must never run for a request that was going to be
     * rejected anyway.
     */
    body: () => string;
    /**
     * Resolves the HMAC secret (per-key or global). Undefined/empty → fail
     * closed (`no_secret`). Called FIRST, before any other check — matching
     * the original middleware, which resolved the secret before touching the
     * timestamp/nonce/signature headers.
     */
    secret: () => string | undefined | Promise<string | undefined>;
    /**
     * Replay-protection scope key, so one principal's nonces never collide
     * with another's. Called ONLY after the HMAC comparison succeeds — a
     * throwing `nonceScope` must never turn an already-malformed request's
     * specific failure reason into a generic `error`, and it must never run
     * for a request whose signature doesn't check out.
     */
    nonceScope: () => string;
    /**
     * Whether the `requireRawBody` precondition is satisfied for this request.
     * Only consulted (and only called) when `config.requireRawBody` is true.
     */
    hasRawBody: () => boolean;
}
export type RequestSignatureVerifyOutcome = {
    type: 'ok';
} | {
    type: 'fail';
    reason: SigningFailureReason;
};
export interface RequestSignatureVerifierCore {
    /** NEVER throws — any internal failure fails CLOSED as a `fail` outcome. */
    verify(input: RequestSignatureVerifyInput): Promise<RequestSignatureVerifyOutcome>;
}
/**
 * Build the framework-agnostic HMAC request-signature verification engine.
 * `verify` mirrors the pre-carve Express middleware's control flow exactly
 * (see the ordering notes on each branch below) but performs NO framework
 * I/O — it never reads a request or writes a response. The adapter (Express,
 * Fastify, ...) does all framework-specific extraction (headers, body,
 * secret resolution, nonce scope) up front and translates the returned
 * outcome into an actual response.
 *
 * FAIL-CLOSED: any failure — unresolved secret, bad/absent
 * timestamp/nonce/signature, replay, or an unavailable nonce store — yields
 * `{ type: 'fail', reason }`. The specific reason is for the caller's own
 * failure/audit hook, never the client.
 *
 * The nonce is consumed ONLY AFTER the signature is proven valid, so an
 * attacker cannot burn a victim's nonce with an unsigned/forged request, and
 * a valid signature can be used at most once within the skew TTL.
 */
export declare function createRequestSignatureVerifierCore(config: RequestSignatureVerifierConfigCore): RequestSignatureVerifierCore;
