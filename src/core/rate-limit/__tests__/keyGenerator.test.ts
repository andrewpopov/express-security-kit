import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import {
  ipKey,
  verifiedIdentityKey,
  defaultKeyGenerator,
  decodedJwtKey,
} from '../keyGenerator';

function req(partial: Partial<Request>): Request {
  return { headers: {}, ...partial } as Request;
}

/** Build an unsigned JWT with the given payload (header.payload.signature). */
function makeJwt(payload: Record<string, unknown>): string {
  const b64 = (obj: unknown) =>
    Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64(payload)}.sig`;
}

describe('ipKey', () => {
  it('keys on req.ip', () => {
    expect(ipKey(req({ ip: '1.2.3.4' }))).toBe('ip:1.2.3.4');
  });
  it('handles missing ip', () => {
    expect(ipKey(req({}))).toBe('ip:unknown');
  });
});

describe('verifiedIdentityKey', () => {
  it('prefers a verified principalId', () => {
    const r = req({ ip: '1.2.3.4', securityContext: { principalType: 'user', principalId: 'u42' } });
    expect(verifiedIdentityKey(r)).toBe('user:u42');
  });
  it('falls back to ip when no context', () => {
    expect(verifiedIdentityKey(req({ ip: '9.9.9.9' }))).toBe('ip:9.9.9.9');
  });
  it('is the exported default', () => {
    expect(defaultKeyGenerator).toBe(verifiedIdentityKey);
  });
});

describe('decodedJwtKey', () => {
  it('keys on the sub claim of a valid Bearer JWT', () => {
    const gen = decodedJwtKey();
    const r = req({
      ip: '1.1.1.1',
      headers: { authorization: `Bearer ${makeJwt({ sub: 'abc123' })}` },
    });
    expect(gen(r)).toBe('user:abc123');
  });

  it('supports a custom claim, prefix, and header', () => {
    const gen = decodedJwtKey({ claim: 'uid', prefix: 'acct', header: 'x-token' });
    const r = req({
      headers: { 'x-token': `Bearer ${makeJwt({ uid: 7 })}` },
    });
    expect(gen(r)).toBe('acct:7');
  });

  it('accepts a raw (non-Bearer) token value', () => {
    const gen = decodedJwtKey();
    const r = req({ headers: { authorization: makeJwt({ sub: 'raw' }) } });
    expect(gen(r)).toBe('user:raw');
  });

  it('falls back to ip on a missing token', () => {
    const gen = decodedJwtKey();
    expect(gen(req({ ip: '2.2.2.2' }))).toBe('ip:2.2.2.2');
  });

  it('falls back to ip on a garbage / non-JWT token', () => {
    const gen = decodedJwtKey();
    expect(gen(req({ ip: '3.3.3.3', headers: { authorization: 'Bearer not-a-jwt' } }))).toBe('ip:3.3.3.3');
    expect(gen(req({ ip: '3.3.3.3', headers: { authorization: 'Bearer a.b.c' } }))).toBe('ip:3.3.3.3');
  });

  it('falls back when the claim is absent', () => {
    const gen = decodedJwtKey();
    const r = req({ ip: '4.4.4.4', headers: { authorization: `Bearer ${makeJwt({ other: 'x' })}` } });
    expect(gen(r)).toBe('ip:4.4.4.4');
  });

  it('uses a custom fallback generator', () => {
    const gen = decodedJwtKey({ fallback: () => 'custom-fallback' });
    expect(gen(req({}))).toBe('custom-fallback');
  });

  it('never throws even when a custom fallback throws (final guard -> ip)', () => {
    const gen = decodedJwtKey({
      fallback: () => {
        throw new Error('fallback boom');
      },
    });
    // No usable token -> fallback throws -> final guard returns ipKey.
    let key!: string;
    expect(() => {
      key = gen(req({ ip: '5.5.5.5' }));
    }).not.toThrow();
    expect(key).toBe('ip:5.5.5.5');
  });

  it('never throws on hostile input', () => {
    const gen = decodedJwtKey();
    const hostile = [
      { headers: { authorization: 'Bearer ...' } },
      { headers: { authorization: `Bearer .${Buffer.from('{bad json').toString('base64url')}.` } },
      { headers: { authorization: ['Bearer', 'array'] as unknown as string } },
      { headers: {} },
    ];
    for (const h of hostile) {
      expect(() => gen(req(h as Partial<Request>))).not.toThrow();
    }
  });
});
