import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { timingSafeEqualHex } from '../hashers';

describe('timingSafeEqualHex — property', () => {
  it('never throws for arbitrary string pairs', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        expect(() => timingSafeEqualHex(a, b)).not.toThrow();
      }),
    );
  });

  it('returns true iff the two strings are byte-identical (utf8)', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        const identical = Buffer.from(a, 'utf8').equals(Buffer.from(b, 'utf8'));
        expect(timingSafeEqualHex(a, b)).toBe(identical);
      }),
    );
  });

  it('an unequal-length pair is always false', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        fc.pre(Buffer.from(a, 'utf8').length !== Buffer.from(b, 'utf8').length);
        expect(timingSafeEqualHex(a, b)).toBe(false);
      }),
    );
  });

  it('is reflexive: any string equals itself', () => {
    fc.assert(
      fc.property(fc.string(), (a) => {
        expect(timingSafeEqualHex(a, a)).toBe(true);
      }),
    );
  });
});
