"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateApiKey = generateApiKey;
exports.parseApiKey = parseApiKey;
exports.maskApiKey = maskApiKey;
exports.rotateApiKey = rotateApiKey;
exports.createThrottledTouchLastUsed = createThrottledTouchLastUsed;
const node_crypto_1 = require("node:crypto");
const hashers_1 = require("./hashers");
/** Mint a new API key. Pure/synchronous — no I/O, no persistence. */
function generateApiKey(options) {
    const prefix = options.prefix;
    if (!prefix) {
        throw new Error('generateApiKey requires a non-empty prefix');
    }
    const hasher = options.hasher ?? (0, hashers_1.sha256Hasher)();
    const keyId = (0, node_crypto_1.randomBytes)(options.keyIdBytes ?? 8).toString('hex');
    const secret = (0, node_crypto_1.randomBytes)(options.secretBytes ?? 32).toString('base64url');
    const raw = `${prefix}${keyId}.${secret}`;
    const hash = hasher(secret);
    const last4 = secret.slice(-4);
    return { raw, hash, keyId, prefix, last4 };
}
/**
 * Parse a raw presented key of the `<prefix><keyId>.<secret>` shape produced
 * by {@link generateApiKey}. Returns `null` (NEVER throws) on any malformed
 * input — callers should treat `null` as a failed auth attempt, not a crash.
 */
function parseApiKey(raw, prefix) {
    if (typeof raw !== 'string' || typeof prefix !== 'string' || prefix.length === 0) {
        return null;
    }
    if (!raw.startsWith(prefix))
        return null;
    const rest = raw.slice(prefix.length);
    const dotIndex = rest.indexOf('.');
    if (dotIndex <= 0)
        return null; // no '.', or nothing before it (empty keyId)
    const keyId = rest.slice(0, dotIndex);
    const secret = rest.slice(dotIndex + 1);
    if (!keyId || !secret)
        return null;
    return { keyId, secret };
}
/**
 * Build a display mask. Superset of smarthome's `prefix...last4` mask and
 * savoro's `<prefix><keyId>.********` mask: shows the full public
 * `prefix`+`keyId` (never secret, and never a table scan to find it — the
 * caller already has it from a lookup) followed by the secret's `last4`, so
 * logs/support can both identify the key by its lookup id AND visually
 * confirm the tail a user reports. Never reveals the secret.
 */
function maskApiKey(material) {
    // Reject anything that isn't real material. Passing the RAW key here is the
    // obvious mistake, and without this guard it produced
    // "undefinedundefined...undefined" — garbage that still LOOKS like a mask, so
    // a consumer would happily store or display it and never notice.
    if (material === null ||
        typeof material !== 'object' ||
        typeof material.prefix !== 'string' ||
        typeof material.keyId !== 'string' ||
        typeof material.last4 !== 'string') {
        throw new TypeError('maskApiKey expects ApiKeyMaterial ({ prefix, keyId, last4 }), not a raw key string');
    }
    return `${material.prefix}${material.keyId}...${material.last4}`;
}
/**
 * Rotate a key: mint fresh material, insert the new record, and revoke
 * `oldKeyId`. Uses `store.transaction` when available for a genuinely atomic
 * swap (old key invalid, new key valid, no window where either both or
 * neither work); without it, inserts the new key before revoking the old one
 * so there is never a window where neither works.
 */
async function rotateApiKey(store, oldKeyId, options) {
    const material = generateApiKey(options);
    const insertRecord = { keyId: material.keyId, hash: material.hash };
    if (store.transaction) {
        await store.transaction(async (tx) => {
            await tx.insert(insertRecord);
            await tx.revoke(oldKeyId);
        });
    }
    else {
        await store.insert(insertRecord);
        await store.revoke(oldKeyId);
    }
    return material;
}
/**
 * Wrap `store.touchLastUsed` so a hot verification path does not write on
 * EVERY request — all four consumer apps currently do exactly that. At most
 * one write per `keyId` per `minIntervalMs` window; calls within the window
 * are dropped (not queued/batched — `lastUsedAt` has a freshness
 * requirement, not a correctness one, so a dropped intermediate update is
 * fine as long as the most recent activity eventually lands).
 *
 * The returned function never throws and never blocks its caller: the write
 * is fired without being awaited, and a rejection is routed to `onError`
 * (never silently swallowed without a seam to observe it).
 */
function createThrottledTouchLastUsed(store, options = {}) {
    const minIntervalMs = options.minIntervalMs ?? 60000;
    const now = options.now ?? Date.now;
    const last = new Map();
    return (keyId) => {
        const t = now();
        const prev = last.get(keyId);
        if (prev !== undefined && t - prev < minIntervalMs)
            return;
        last.set(keyId, t);
        void store.touchLastUsed(keyId, new Date(t)).catch((err) => {
            options.onError?.(keyId, err);
        });
    };
}
