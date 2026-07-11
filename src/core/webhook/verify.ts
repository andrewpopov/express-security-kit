import {
  createHmac,
  createPublicKey,
  timingSafeEqual,
  verify as cryptoVerify,
} from 'node:crypto';

import type { NonceStore } from '../signing/nonceStore';
import { sha256Hex } from '../signing/signRequest';

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

// ---------------------------------------------------------------------------
// Header contract (C8)
// ---------------------------------------------------------------------------

/** Narrow header record this verifier accepts — deliberately NOT Express's `IncomingHttpHeaders`. */
export type WebhookHeaders = Record<string, string | string[] | undefined>;

/**
 * A safe, case-insensitive, single-value header reader handed to config
 * resolvers (secret/publicKey/replay-scope) so they never have to reimplement
 * the same case-insensitivity / ambiguity handling this verifier uses
 * internally.
 */
export type HeaderReader = (name: string) => string | undefined;

function collectMatches(
  headers: WebhookHeaders,
  name: string,
): (string | string[] | undefined)[] {
  const lower = name.toLowerCase();
  const matches: (string | string[] | undefined)[] = [];
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      matches.push(headers[key]);
    }
  }
  return matches;
}

/**
 * Case-insensitive single-value header read, TRIMMED. Returns `undefined` —
 * treated identically to "absent" by every caller — when the header is
 * genuinely absent OR ambiguous: present as an array (duplicate headers some
 * frameworks surface as `string[]`), present under more than one case-variant
 * key simultaneously, or a value containing a raw comma (the byte sequence
 * Node's http module uses to join genuinely-duplicated headers into one
 * string). None of the values this verifier reads (hex signatures, decimal
 * timestamps) legitimately contain a comma, so any comma is treated as an
 * ambiguous duplicate rather than guessed at (C8: reject, don't guess).
 */
function readHeaderTrimmed(headers: WebhookHeaders, name: string): string | undefined {
  const matches = collectMatches(headers, name);
  if (matches.length !== 1) return undefined;
  const value = matches[0];
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.includes(',')) return undefined;
  return trimmed;
}

/**
 * Case-insensitive single-value header read, UNTRIMMED. Used ONLY to pull the
 * raw bytes of the ed25519 timestamp header for message construction (C5):
 * the signer computed their signature over the EXACT bytes of that header, so
 * the verifier must reproduce those exact bytes rather than a
 * whitespace-normalized copy — otherwise a request whose timestamp header was
 * tampered with (extra whitespace, a re-serialized/leading-zero variant)
 * would be silently normalized back to the originally-signed value instead of
 * failing signature verification. Still rejects array/multi-key/comma-joined
 * ambiguity, same as {@link readHeaderTrimmed}.
 */
function readHeaderRaw(headers: WebhookHeaders, name: string): string | undefined {
  const matches = collectMatches(headers, name);
  if (matches.length !== 1) return undefined;
  const value = matches[0];
  if (typeof value !== 'string') return undefined;
  if (value.length === 0) return undefined;
  if (value.includes(',')) return undefined;
  return value;
}

function buildHeaderReader(headers: WebhookHeaders): HeaderReader {
  return (name: string) => readHeaderTrimmed(headers, name);
}

// ---------------------------------------------------------------------------
// Config (C1: true discriminated union on `scheme`)
// ---------------------------------------------------------------------------

/** Resolves the shared HMAC secret. May be async; absence -> `missing_secret`. */
export type SecretResolver = (
  headers: HeaderReader,
) => string | undefined | Promise<string | undefined>;

/** Resolves the ed25519 public key (hex). May be async; absence -> `missing_public_key`. */
export type PublicKeyResolver = (
  headers: HeaderReader,
) => string | undefined | Promise<string | undefined>;

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

// ---------------------------------------------------------------------------
// Outcome (C3)
// ---------------------------------------------------------------------------

export type WebhookVerifyReason =
  | 'missing_secret'
  | 'missing_public_key'
  | 'missing_signature'
  | 'bad_signature'
  | 'missing_body'
  | 'missing_timestamp'
  | 'invalid_timestamp'
  | 'stale_timestamp'
  | 'missing_replay_id'
  | 'replay'
  | 'store_unavailable'
  | 'invalid_config';

export type WebhookVerifyOutcome =
  | { ok: true }
  | { ok: false; reason: WebhookVerifyReason };

function fail(reason: WebhookVerifyReason): WebhookVerifyOutcome {
  return { ok: false, reason };
}

const OK: WebhookVerifyOutcome = { ok: true };

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function toBuffer(body: string | Buffer): Buffer {
  return Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
}

const HEX_CHARS_EVEN_LENGTH = /^(?:[0-9a-fA-F]{2})+$/;

/**
 * Run the replay-protection step shared by both schemes: derive the
 * (authenticated) replay id and atomically consume it under the configured
 * (static) scope. Only ever reached AFTER the signature has been verified
 * (C4) — callers must not invoke this earlier.
 */
async function consumeReplay(
  replay: ReplayConfig,
  rawBody: string | Buffer,
  defaultReplayId: string,
): Promise<WebhookVerifyOutcome | null> {
  const replayId = replay.idFromVerifiedBody
    ? replay.idFromVerifiedBody(rawBody)
    : defaultReplayId;
  if (!replayId) {
    return fail('missing_replay_id');
  }

  try {
    const result = await replay.store.consume(replay.scope, replayId, replay.ttlMs);
    if (result === 'replay') return fail('replay');
    // Fail CLOSED on anything other than the exact 'ok' sentinel — a
    // misbehaving/non-conformant store (undefined, null, 'OK', or any other
    // garbage return) must never be treated as a successful consume. Only an
    // exact 'ok' proves the nonce was actually recorded.
    if (result !== 'ok') return fail('store_unavailable');
  } catch {
    return fail('store_unavailable');
  }

  return null;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

async function resolveHmacSecret(
  config: HmacSha256Config,
  headers: HeaderReader,
): Promise<string | undefined> {
  try {
    const value = typeof config.secret === 'function' ? await config.secret(headers) : config.secret;
    return value && value.length > 0 ? value : undefined;
  } catch {
    return undefined;
  }
}

async function verifyHmacSha256(
  config: HmacSha256Config,
  rawBody: string | Buffer | undefined,
  rawHeaders: WebhookHeaders,
): Promise<WebhookVerifyOutcome> {
  const headers = buildHeaderReader(rawHeaders);

  // 1. Resolve credential FIRST (C4) — an unresolvable secret must never let
  //    the request reach signature comparison or the nonce store.
  const secret = await resolveHmacSecret(config, headers);
  if (secret === undefined) return fail('missing_secret');

  // 2. Read + strictly validate the signed inputs (signature header, body).
  const signatureHeaderName = config.signatureHeader ?? 'x-hub-signature-256';
  const digestPrefix = config.digestPrefix ?? 'sha256=';

  const headerValue = readHeaderTrimmed(rawHeaders, signatureHeaderName);
  if (headerValue === undefined) return fail('missing_signature');

  if (!headerValue.startsWith(digestPrefix)) {
    // Present but structurally wrong — a malformed/forged value, not an
    // absent one.
    return fail('bad_signature');
  }
  const providedHex = headerValue.slice(digestPrefix.length);
  if (!HEX_CHARS_EVEN_LENGTH.test(providedHex)) {
    return fail('bad_signature');
  }

  if (rawBody === undefined) return fail('missing_body');
  const bodyBuffer = toBuffer(rawBody);

  // 3. Verify the signature (fail -> bad_signature). The explicit length
  //    pre-check runs BEFORE timingSafeEqual so a mismatched-length digest
  //    is rejected deterministically rather than by relying on
  //    timingSafeEqual's own throw-on-mismatch behavior.
  const computed = createHmac('sha256', secret).update(bodyBuffer).digest();
  const provided = Buffer.from(providedHex, 'hex');
  if (computed.length !== provided.length) {
    return fail('bad_signature');
  }
  if (!timingSafeEqual(computed, provided)) {
    return fail('bad_signature');
  }

  // No timestamp handling for this scheme (C2): GitHub-style HMAC signs only
  // the body, so there is no authenticated timestamp to validate.

  // 4. Replay protection — reached ONLY after a verified signature (C4).
  if (config.replay) {
    const defaultReplayId = sha256Hex(providedHex.toLowerCase());
    const replayOutcome = await consumeReplay(config.replay, rawBody, defaultReplayId);
    if (replayOutcome) return replayOutcome;
  }

  return OK;
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

const ED25519_PUBLIC_KEY_HEX = /^[0-9a-fA-F]{64}$/;
const ED25519_SIGNATURE_HEX = /^[0-9a-fA-F]{128}$/;
// DER SPKI prefix for a raw 32-byte ed25519 public key.
const ED25519_SPKI_PREFIX_HEX = '302a300506032b6570032100';
const STRICT_DECIMAL_INTEGER = /^[0-9]+$/;

async function resolveEd25519PublicKeyHex(
  config: Ed25519Config,
  headers: HeaderReader,
): Promise<string | undefined> {
  try {
    const value =
      typeof config.publicKey === 'function' ? await config.publicKey(headers) : config.publicKey;
    return value && value.length > 0 ? value : undefined;
  } catch {
    return undefined;
  }
}

/** Strict decimal-integer parse: rejects non-finite/fractional/signed/trailing-char/whitespace input. */
function parseStrictSecondsTimestamp(raw: string): number | null {
  if (!STRICT_DECIMAL_INTEGER.test(raw)) return null;
  const value = Number(raw);
  return Number.isFinite(value) ? value : null;
}

async function verifyEd25519(
  config: Ed25519Config,
  rawBody: string | Buffer | undefined,
  rawHeaders: WebhookHeaders,
): Promise<WebhookVerifyOutcome> {
  const headers = buildHeaderReader(rawHeaders);

  // 1. Resolve credential FIRST (C4).
  const publicKeyHex = await resolveEd25519PublicKeyHex(config, headers);
  if (publicKeyHex === undefined) return fail('missing_public_key');
  if (!ED25519_PUBLIC_KEY_HEX.test(publicKeyHex)) {
    // An invalid CONFIGURED key is a config error, never a per-request
    // forgery signal (C5).
    return fail('missing_public_key');
  }

  // 2. Read + strictly validate the signed inputs: signature header,
  //    timestamp header (raw bytes, preserved exactly — C5), body.
  const signatureHeaderName = config.signatureHeader ?? 'x-signature-ed25519';
  const signatureHex = readHeaderTrimmed(rawHeaders, signatureHeaderName);
  if (signatureHex === undefined) return fail('missing_signature');
  if (!ED25519_SIGNATURE_HEX.test(signatureHex)) {
    // Present but structurally wrong — malformed/forged, not absent.
    return fail('bad_signature');
  }

  const rawTimestamp = readHeaderRaw(rawHeaders, config.timestamp.header);
  if (rawTimestamp === undefined) return fail('missing_timestamp');

  if (rawBody === undefined) return fail('missing_body');
  const bodyBuffer = toBuffer(rawBody);

  // 3. Verify the signature (fail -> bad_signature; a resolver/crypto/config
  //    EXCEPTION during key construction or verification is NOT bad_signature
  //    — it means the configured key material is unusable, so it surfaces as
  //    missing_public_key rather than mislabeling a config problem as forgery).
  const message = Buffer.concat([Buffer.from(rawTimestamp, 'utf8'), bodyBuffer]);
  const signatureBuffer = Buffer.from(signatureHex, 'hex');

  let verified: boolean;
  try {
    const der = Buffer.concat([
      Buffer.from(ED25519_SPKI_PREFIX_HEX, 'hex'),
      Buffer.from(publicKeyHex, 'hex'),
    ]);
    const keyObject = createPublicKey({ key: der, format: 'der', type: 'spki' });
    verified = cryptoVerify(null, message, keyObject, signatureBuffer);
  } catch {
    return fail('missing_public_key');
  }
  if (!verified) return fail('bad_signature');

  // 4. Parse + enforce the AUTHENTICATED timestamp skew (only now that the
  //    signature — which covers this exact header string — has verified).
  const parsedSeconds = parseStrictSecondsTimestamp(rawTimestamp);
  if (parsedSeconds === null) return fail('invalid_timestamp');

  // A non-finite/negative maxSkewSeconds is a CONFIG error, not a per-request
  // signal — NaN/Infinity would make every comparison below vacuously true
  // (any skew is "within" an Infinity/NaN window), silently disabling
  // freshness enforcement entirely. Fail closed rather than verify ok.
  if (
    !Number.isFinite(config.timestamp.maxSkewSeconds) ||
    config.timestamp.maxSkewSeconds < 0
  ) {
    return fail('invalid_config');
  }

  const nowMs = config.timestamp.now ? config.timestamp.now() : Date.now();
  // A non-finite injected clock is likewise a config/environment error — it
  // would make `skewSeconds` NaN, and `NaN > maxSkewSeconds` is always
  // `false`, so an old/stale signed request would sail through as fresh.
  if (!Number.isFinite(nowMs)) {
    return fail('invalid_config');
  }
  const skewSeconds = Math.abs(nowMs / 1000 - parsedSeconds);
  if (skewSeconds > config.timestamp.maxSkewSeconds) return fail('stale_timestamp');

  // 5. Replay protection — reached ONLY after a verified signature (C4).
  if (config.replay) {
    const defaultReplayId = sha256Hex(signatureHex.toLowerCase());
    const replayOutcome = await consumeReplay(config.replay, rawBody, defaultReplayId);
    if (replayOutcome) return replayOutcome;
  }

  return OK;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

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
export function verifyWebhookSignature(
  input: WebhookVerifyInput,
): Promise<WebhookVerifyOutcome> {
  const { rawBody, headers, config } = input;
  if (config.scheme === 'hmac-sha256') {
    return verifyHmacSha256(config, rawBody, headers);
  }
  return verifyEd25519(config, rawBody, headers);
}
