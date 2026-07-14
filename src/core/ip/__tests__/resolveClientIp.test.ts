import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import { resolveClientIp } from '../resolveClientIp';

function req(partial: Partial<Request>): Request {
  return { headers: {}, ...partial } as Request;
}

describe('resolveClientIp: default (no options)', () => {
  it('regression guard: with no options set, resolves to req.ip only — matching pre-1.4.0 ipKey behavior', () => {
    // ipKey (pre-existing) computes `ip:${req.ip}` directly with no
    // normalization. resolveClientIp with no trust flags falls straight
    // through to req.ip too, so a consumer that never opts into
    // trustCloudflare/trustXff gets the same underlying IP either way.
    expect(resolveClientIp(req({ ip: '203.0.113.9' }))).toBe('203.0.113.9');
  });

  it('ignores Cf-Connecting-Ip and X-Forwarded-For when neither trust flag is set', () => {
    const r = req({
      ip: '203.0.113.9',
      headers: {
        'cf-connecting-ip': '198.51.100.1',
        'x-forwarded-for': '1.2.3.4, 8.8.8.8',
      },
    });
    expect(resolveClientIp(r)).toBe('203.0.113.9');
  });

  it('resolves to empty string when req.ip is absent', () => {
    expect(resolveClientIp(req({}))).toBe('');
  });
});

describe('resolveClientIp: trustCloudflare', () => {
  it('prefers Cf-Connecting-Ip over req.ip', () => {
    const r = req({ ip: '10.0.0.1', headers: { 'cf-connecting-ip': '203.0.113.7' } });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('203.0.113.7');
  });

  it('prefers Cf-Connecting-Ip over X-Forwarded-For even when both trust flags are on', () => {
    const r = req({
      headers: { 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '9.9.9.9, 8.8.8.8' },
    });
    expect(resolveClientIp(r, { trustCloudflare: true, trustXff: true })).toBe('203.0.113.7');
  });

  it('falls through when Cf-Connecting-Ip is absent', () => {
    const r = req({ ip: '10.0.0.1', headers: {} });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('10.0.0.1');
  });

  it('falls through when Cf-Connecting-Ip is an empty string', () => {
    const r = req({ ip: '10.0.0.1', headers: { 'cf-connecting-ip': '' } });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('10.0.0.1');
  });

  it('handles an array-valued Cf-Connecting-Ip header (takes the first entry)', () => {
    const r = req({ headers: { 'cf-connecting-ip': ['203.0.113.7', '198.51.100.1'] as unknown as string } });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('203.0.113.7');
  });
});

describe('resolveClientIp: trustXff — the ROG-1094 spoof-closure', () => {
  it('ADVERSARIAL: a spoofed LEADING XFF hop does not change the resolved IP — the last (edge-appended) hop wins', () => {
    // "1.2.3.4" is what an attacker would inject as their own X-Forwarded-For
    // value; "203.0.113.7" is the hop appended by the real (trusted) proxy.
    // If the first hop won, this would BE the bypass this feature closes.
    const spoofed = req({ headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.7' } });
    expect(resolveClientIp(spoofed, { trustXff: true })).toBe('203.0.113.7');
  });

  it('ADVERSARIAL: rotating the forged leading hop does not change the resolved key', () => {
    const a = resolveClientIp(
      req({ headers: { 'x-forwarded-for': '1.1.1.1, 203.0.113.7' } }),
      { trustXff: true },
    );
    const b = resolveClientIp(
      req({ headers: { 'x-forwarded-for': '2.2.2.2, 203.0.113.7' } }),
      { trustXff: true },
    );
    expect(a).toBe(b);
    expect(a).toBe('203.0.113.7');
  });

  it('single-hop XFF resolves to that one hop', () => {
    const r = req({ headers: { 'x-forwarded-for': '203.0.113.7' } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('203.0.113.7');
  });

  it('multi-hop XFF (3+ hops) resolves to the last hop', () => {
    const r = req({ headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.7' } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('203.0.113.7');
  });

  it('falls through to req.ip on an empty XFF header', () => {
    const r = req({ ip: '10.0.0.1', headers: { 'x-forwarded-for': '' } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('10.0.0.1');
  });

  it('falls through to req.ip when XFF is absent entirely', () => {
    const r = req({ ip: '10.0.0.1', headers: {} });
    expect(resolveClientIp(r, { trustXff: true })).toBe('10.0.0.1');
  });

  it('handles an array-valued XFF header (takes the first entry, then its last hop)', () => {
    const r = req({ headers: { 'x-forwarded-for': ['1.1.1.1, 203.0.113.7', 'ignored'] as unknown as string } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('203.0.113.7');
  });

  it('trims whitespace around the last hop', () => {
    const r = req({ headers: { 'x-forwarded-for': '1.1.1.1,   203.0.113.7  ' } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('203.0.113.7');
  });

  it('falls through to req.ip when the last XFF hop is empty (trailing comma)', () => {
    const r = req({ ip: '10.0.0.1', headers: { 'x-forwarded-for': '1.1.1.1, ' } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('10.0.0.1');
  });
});

describe('resolveClientIp: normalization', () => {
  it('normalizes an IPv4-mapped IPv6 req.ip', () => {
    const r = req({ ip: '::ffff:203.0.113.7' });
    expect(resolveClientIp(r)).toBe('203.0.113.7');
  });

  it('normalizes an IPv4-mapped IPv6 XFF hop', () => {
    const r = req({ headers: { 'x-forwarded-for': '::ffff:203.0.113.7' } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('203.0.113.7');
  });

  it('normalizes an IPv4-mapped IPv6 Cf-Connecting-Ip', () => {
    const r = req({ headers: { 'cf-connecting-ip': '::ffff:203.0.113.7' } });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('203.0.113.7');
  });

  it('canonicalizes the IPv6 loopback to 127.0.0.1', () => {
    expect(resolveClientIp(req({ ip: '::1' }))).toBe('127.0.0.1');
  });
});

describe('resolveClientIp: never throws on garbage input', () => {
  it('survives a missing headers object entirely', () => {
    const hostile = { ip: '1.2.3.4' } as unknown as Request;
    expect(() => resolveClientIp(hostile, { trustCloudflare: true, trustXff: true })).not.toThrow();
  });

  it('survives a null req', () => {
    expect(() => resolveClientIp(null as unknown as Request)).not.toThrow();
    expect(resolveClientIp(null as unknown as Request)).toBe('');
  });

  it('survives a non-string, non-array XFF value', () => {
    const r = req({ ip: '10.0.0.1', headers: { 'x-forwarded-for': 42 as unknown as string } });
    expect(resolveClientIp(r, { trustXff: true })).toBe('10.0.0.1');
  });

  it('survives a non-string, non-array Cf-Connecting-Ip value', () => {
    const r = req({ ip: '10.0.0.1', headers: { 'cf-connecting-ip': {} as unknown as string } });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('10.0.0.1');
  });

  it('caps an absurdly long header value rather than propagating it as the key', () => {
    const long = '9'.repeat(10_000);
    const r = req({ headers: { 'cf-connecting-ip': long } });
    const resolved = resolveClientIp(r, { trustCloudflare: true });
    expect(resolved.length).toBeLessThanOrEqual(64);
  });
});
