import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import type { Request } from 'express';
import { decodedJwtKey } from '../keyGenerator';

function req(headers: Record<string, unknown>): Request {
  return { headers, ip: '1.2.3.4' } as unknown as Request;
}

describe('decodedJwtKey — property (never throws on arbitrary header garbage)', () => {
  const gen = decodedJwtKey();

  it('always returns a string for an arbitrary string/array/undefined authorization header', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.string({ maxLength: 60 }),
          fc.array(fc.string({ maxLength: 30 }), { maxLength: 5 }),
          fc.constant(undefined),
        ),
        (headerValue) => {
          const r = req({ authorization: headerValue });
          let key!: string;
          expect(() => {
            key = gen(r);
          }).not.toThrow();
          expect(typeof key).toBe('string');
        },
      ),
    );
  });

  it('always returns a string even for arbitrary dot-delimited "JWT-shaped" garbage', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 30 }),
        fc.string({ maxLength: 30 }),
        fc.string({ maxLength: 30 }),
        (a, b, c) => {
          const r = req({ authorization: `Bearer ${a}.${b}.${c}` });
          let key!: string;
          expect(() => {
            key = gen(r);
          }).not.toThrow();
          expect(typeof key).toBe('string');
        },
      ),
    );
  });
});
