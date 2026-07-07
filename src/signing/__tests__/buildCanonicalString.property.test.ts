import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { buildCanonicalString, sha256Hex } from '../signRequest';

/**
 * NOTE on framing (deliberately narrow — see the maturation plan's Codex
 * adjustments): this does NOT claim sha256 collision-freedom, and it does NOT
 * claim distinct raw input tuples always produce distinct canonical strings
 * (they don't: `method` is upper-cased, and GET/HEAD zero the body). The real
 * invariant under test is that for CR/LF-free `method`/`url`/`nonce`, the
 * 5-line LF-joined canonical string has NO delimiter ambiguity — splitting it
 * back on `\n` always recovers exactly the 5 NORMALIZED fields, byte for
 * byte. Plus: any `\n`/`\r` in `method`, `url`, or `nonce` throws (the guard
 * added for the LF-injection fix).
 */

const noCrlfString = () =>
  fc.string({ maxLength: 40 }).filter((s) => !/[\r\n]/.test(s));

const timestampArb = fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER });
const bodyArb = fc.string({ maxLength: 40 });

function isBodylessMethod(method: string): boolean {
  const m = method.toUpperCase();
  return m === 'GET' || m === 'HEAD';
}

describe('buildCanonicalString — property (splits into exactly 5 recoverable fields)', () => {
  it('for CR/LF-free method/url/nonce, splitting on \\n recovers the 5 normalized fields exactly', () => {
    fc.assert(
      fc.property(
        noCrlfString(),
        noCrlfString(),
        timestampArb,
        noCrlfString(),
        bodyArb,
        (method, url, timestampMs, nonce, body) => {
          const canonical = buildCanonicalString({ method, url, timestampMs, nonce, body });
          const parts = canonical.split('\n');

          expect(parts).toHaveLength(5);
          expect(parts[0]).toBe(method.toUpperCase());
          expect(parts[1]).toBe(url);
          expect(parts[2]).toBe(String(timestampMs));
          expect(parts[3]).toBe(nonce);

          const expectedBodyHash = isBodylessMethod(method) ? sha256Hex('') : sha256Hex(body);
          expect(parts[4]).toBe(expectedBodyHash);
          expect(parts[4]).toMatch(/^[a-f0-9]{64}$/);
        },
      ),
    );
  });

  it('any \\n or \\r injected into method, url, or nonce throws', () => {
    fc.assert(
      fc.property(
        noCrlfString(),
        noCrlfString(),
        timestampArb,
        noCrlfString(),
        fc.constantFrom('\n', '\r'),
        fc.constantFrom<'method' | 'url' | 'nonce'>('method', 'url', 'nonce'),
        (method, url, timestampMs, nonce, badChar, which) => {
          const input = { method, url, timestampMs, nonce, body: '' };
          input[which] = input[which] + badChar;
          expect(() => buildCanonicalString(input)).toThrow(/must not contain CR\/LF/);
        },
      ),
    );
  });
});
