import { describe, it, expect } from 'vitest';
import {
  buildCanonicalString,
  signRequest,
  sha256Hex,
} from '../signRequest';

const SECRET = 'test-signing-secret';

// Authoritative golden vectors — independently computed. Any drift here means
// the scheme diverged from stoki's live clients.
const POST = {
  method: 'POST',
  url: '/api/lists/abc123/items?sort=name',
  timestampMs: 1700000000000,
  nonce: 'nonce-abcdef12345678',
  body: JSON.stringify({ name: 'Milk', qty: 2 }),
};
const POST_BODY_HASH =
  '925abda07ddf6ee82b4158d590e5d5d7329538b9b68c703bc4de8be6045a2aab';
const POST_SIG =
  '037275e45d7c28f1bce1253bc4a5af481331c457cf4d99e57073eb076771cd48';

const GET = {
  method: 'GET',
  url: '/api/lists/abc123',
  timestampMs: 1700000000000,
  nonce: 'nonce-getreq000001',
  body: '',
};
const GET_SIG =
  '478fdd33b69ce04214396c2f5f73bb19f7b8ab665afaebebd5b5bf19e807f857';

const EMPTY_SHA =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('sha256Hex', () => {
  it("sha256hex('') is the known empty-string constant", () => {
    expect(sha256Hex('')).toBe(EMPTY_SHA);
  });
});

describe('buildCanonicalString', () => {
  it('joins 5 LF-separated lines with the POST body hash', () => {
    const canonical = buildCanonicalString(POST);
    expect(canonical).toBe(
      [
        'POST',
        '/api/lists/abc123/items?sort=name',
        '1700000000000',
        'nonce-abcdef12345678',
        POST_BODY_HASH,
      ].join('\n'),
    );
  });

  it('uses sha256("") for GET regardless of any body passed', () => {
    const canonical = buildCanonicalString({ ...GET, body: 'ignored' });
    expect(canonical.split('\n')[4]).toBe(EMPTY_SHA);
  });

  it('upper-cases the method', () => {
    const c = buildCanonicalString({ ...POST, method: 'post' });
    expect(c.split('\n')[0]).toBe('POST');
  });
});

describe('signRequest — golden vectors', () => {
  it('reproduces the POST vector exactly', () => {
    const { signature, headers } = signRequest({ secret: SECRET, ...POST });
    expect(signature).toBe(POST_SIG);
    expect(headers).toEqual({
      'X-Timestamp': '1700000000000',
      'X-Nonce': 'nonce-abcdef12345678',
      'X-Signature': POST_SIG,
    });
  });

  it('reproduces the GET vector exactly (empty body)', () => {
    const { signature } = signRequest({ secret: SECRET, ...GET });
    expect(signature).toBe(GET_SIG);
  });

  it('signature is 64 lowercase hex', () => {
    const { signature } = signRequest({ secret: SECRET, ...POST });
    expect(signature).toMatch(/^[a-f0-9]{64}$/);
  });
});
