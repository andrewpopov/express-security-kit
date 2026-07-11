import type { NonceStore } from '../signing/nonceStore';
/**
 * Framework-agnostic inbound webhook signature verification. Per the design's
 * scope split (see phase2-design.md, Module 2), this file does SIGNATURE
 * VERIFICATION ONLY — no express/fastify import, no HTTP response shaping.
 * The express adapter (a follow-up module) maps `WebhookVerifyReason` to a
 * status code (missing_secret/missing_public_key/store_unavailable -> 503,
 * everything else -> 401) and a generic body.
 *
 * THE CRITICAL INVARIANT (C2): every security decision here — the replay
 * identity, in particular — is derived ONLY from material that is covered by
 * the verified signature. Nothing here ever keys a decision off an
 * unauthenticated header (e.g. a delivery/id header the sender chose and
 * could resend with a different value).
 */
/** Narrow header record this verifier accepts — deliberately NOT Express's `IncomingHttpHeaders`. */
export type WebhookHeaders = Record<string, string | string[] | undefined>;
/**
 * A safe, case-insensitive, single-value header reader handed to config
 * resolvers (secret/publicKey/replay-scope) so they never have to reimplement
 * the same case-insensitivity / ambiguity handling this verifier uses
 * internally.
 */
export type HeaderReader = (name: string) => string | undefined;
/** Resolves the shared HMAC secret. May be async; absence -> `missing_secret`. */
export type SecretResolver = (headers: HeaderReader) => string | undefined | Promise<string | undefined>;
/** Resolves the ed25519 public key (hex). May be async; absence -> `missing_public_key`. */
export type PublicKeyResolver = (headers: HeaderReader) => string | undefined | Promise<string | undefined>;
/**
 * Extract an application-level replay id from the (already-verified) body.
 * Because the body is covered by the signature, an id pulled from it is
 * authenticated — unlike any request header the sender is free to vary.
 * Absence (`undefined`) -> `missing_replay_id`.
 */
export type ReplayIdFromVerifiedBody = (body: string | Buffer) => string | undefined;
/**
 * Replay protection is ONE all-or-nothing block (C9) — `store`, `scope`, and
 * `ttlMs` are required together; there is no partially-enabled replay config.
 */
export interface ReplayConfig {
    /** Durable (ideally cross-instance) nonce store. A throw from `consume()` -> `store_unavailable`, never `replay`. */
    store: NonceStore;
    /**
     * Replay scope/namespace (e.g. a webhook source name) — a STATIC string,
     * fixed at configuration time.
     *
     * Deliberately NOT resolvable from the request (no `(headers) => string`
     * form): headers are unauthenticated until the signature check below has
     * run, and an attacker can freely vary any header while replaying a
     * previously-valid (body, signature) pair. A scope derived from such a
     * header would hand that replay a fresh nonce namespace on every attempt —
     * defeating replay protection entirely (C2). If per-source namespacing is
     * needed, configure one verifier instance per scope (e.g. one
     * `WebhookVerifyConfig` per webhook source) rather than branching scope off
     * request data.
     */
    scope: string;
    /** Nonce TTL in ms. Must be > 0 (enforced by the store; a store throw on an invalid ttlMs surfaces as `store_unavailable`). */
    ttlMs: number;
    /**
     * Optional authenticated replay-id extractor. Defaults to
     * `sha256hex(<verified signature>)` — see {@link ReplayIdFromVerifiedBody}.
     */
    idFromVerifiedBody?: ReplayIdFromVerifiedBody;
}
export interface HmacSha256Config {
    scheme: 'hmac-sha256';
    /** Shared secret. May be a resolver (e.g. per-source secret lookup); absence -> `missing_secret`. */
    secret: string | SecretResolver;
    publicKey?: never;
    /** Header carrying the signature. Default `'x-hub-signature-256'`. */
    signatureHeader?: string;
    /** Prefix on the signature header value. Default `'sha256='`. */
    digestPrefix?: string;
    /**
     * GitHub-style HMAC signs the body ONLY — there is no signed timestamp to
     * validate (C2), so this scheme has no `timestamp` field. A future
     * Stripe-style signed-timestamp HMAC variant would need a distinct scheme,
     * not a bolt-on here.
     */
    replay?: ReplayConfig;
}
export interface Ed25519TimestampConfig {
    /** Header carrying the timestamp that is part of the signed message. */
    header: string;
    /** Maximum allowed |now - timestamp| in seconds. */
    maxSkewSeconds: number;
    /** Injectable clock (ms epoch), for tests. Default `Date.now`. */
    now?: () => number;
}
export interface Ed25519Config {
    scheme: 'ed25519';
    /** Hex-encoded ed25519 public key (`^[0-9a-fA-F]{64}$`). May be a resolver; absence/invalid -> `missing_public_key`. */
    publicKey: string | PublicKeyResolver;
    secret?: never;
    /** Header carrying the signature. Default `'x-signature-ed25519'`. */
    signatureHeader?: string;
    /**
     * REQUIRED: ed25519's signed message is `timestamp + body` (C2/C5), so
     * timestamp handling is not optional the way it is for body-only HMAC.
     */
    timestamp: Ed25519TimestampConfig;
    replay?: ReplayConfig;
}
export type WebhookVerifyConfig = HmacSha256Config | Ed25519Config;
export interface WebhookVerifyInput {
    /** Raw (unparsed) request body exactly as received. `undefined` means "no raw-body capture" -> `missing_body`, distinct from a legitimate empty body (`''`/`Buffer.alloc(0)`). */
    rawBody: string | Buffer | undefined;
    headers: WebhookHeaders;
    config: WebhookVerifyConfig;
}
export type WebhookVerifyReason = 'missing_secret' | 'missing_public_key' | 'missing_signature' | 'bad_signature' | 'missing_body' | 'missing_timestamp' | 'invalid_timestamp' | 'stale_timestamp' | 'missing_replay_id' | 'replay' | 'store_unavailable' | 'invalid_config';
export type WebhookVerifyOutcome = {
    ok: true;
} | {
    ok: false;
    reason: WebhookVerifyReason;
};
/**
 * Verify an inbound webhook request's signature, returning a discriminated
 * outcome WITHOUT sending HTTP. Async because credential resolvers and
 * {@link NonceStore.consume} are async (C9).
 *
 * Ordering (C4) guarantees an unauthenticated request never reaches the
 * nonce store: resolve credential -> read/validate signature + signed inputs
 * -> verify signature -> (ed25519) enforce authenticated timestamp skew ->
 * derive authenticated replay id -> consume -> ok.
 */
export declare function verifyWebhookSignature(input: WebhookVerifyInput): Promise<WebhookVerifyOutcome>;
