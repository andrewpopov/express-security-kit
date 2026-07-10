import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import {
  sha256Hasher,
  scopedHmacHasher,
  timingSafeEqualHex,
} from '../hashers';

describe('sha256Hasher', () => {
  it('matches a known SHA-256 vector', () => {
    // sha256('abc') is a well-known constant.
    const known =
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    expect(sha256Hasher()('abc')).toBe(known);
  });

  it('matches node crypto for an arbitrary raw key', () => {
    const raw = 'ssk_ak_deadbeefcafebabe';
    const expected = createHash('sha256').update(raw).digest('hex');
    expect(sha256Hasher()(raw)).toBe(expected);
  });
});

describe('scopedHmacHasher', () => {
  it('reproduces HMAC-SHA256(secret:scope, rawKey) exactly (smarthome format)', () => {
    const secret = 'super-secret';
    const scope = 'integrations';
    const raw = 'smh_livekey_123';
    const expected = createHmac('sha256', `${secret}:${scope}`)
      .update(raw)
      .digest('hex');
    expect(scopedHmacHasher(secret, scope)(raw)).toBe(expected);
  });

  it('differs when scope differs', () => {
    const a = scopedHmacHasher('s', 'scopeA')('k');
    const b = scopedHmacHasher('s', 'scopeB')('k');
    expect(a).not.toBe(b);
  });
});

describe('timingSafeEqualHex', () => {
  it('returns true for equal strings', () => {
    expect(timingSafeEqualHex('deadbeef', 'deadbeef')).toBe(true);
  });

  it('returns false for equal-length but different strings', () => {
    expect(timingSafeEqualHex('deadbeef', 'deadbeff')).toBe(false);
  });

  it('returns false on length mismatch without throwing', () => {
    expect(timingSafeEqualHex('deadbeef', 'deadbe')).toBe(false);
    expect(timingSafeEqualHex('', 'x')).toBe(false);
  });

  it('never throws on odd/garbage input', () => {
    expect(() => timingSafeEqualHex('', '')).not.toThrow();
    expect(timingSafeEqualHex('', '')).toBe(true);
    expect(() =>
      timingSafeEqualHex('not-hex-!!', 'also-weird'),
    ).not.toThrow();
  });
});
