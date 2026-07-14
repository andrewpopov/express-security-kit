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

function reqWithSocket(partial: Partial<Request> & { remoteAddress?: string }): Request {
  const { remoteAddress, ...rest } = partial;
  return {
    headers: {},
    ...rest,
    socket: remoteAddress === undefined ? undefined : { remoteAddress },
  } as unknown as Request;
}

describe('resolveClientIp: trustedPeers (GAP 2 — fidash peer gate)', () => {
  it('regression guard: trustedPeers unset (default) behaves exactly like pre-1.5.0 — cf honored regardless of peer', () => {
    const r = reqWithSocket({
      ip: '10.0.0.1',
      remoteAddress: '203.0.113.50',
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    // No trustedPeers option: peer gate never engages, matching the
    // pre-existing trustCloudflare-only behavior byte-for-byte.
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('198.51.100.1');
  });

  it('ADVERSARIAL / CANARY TARGET: blocks a spoofed Cf-Connecting-Ip from a NON-trusted peer', () => {
    // A direct LAN/localhost attacker who never went through Cloudflare or
    // the reverse proxy connects straight to the Express port and forges
    // cf-connecting-ip. Without the peer gate this would be honored.
    const r = reqWithSocket({
      remoteAddress: '203.0.113.66', // NOT in trustedPeers, not loopback
      headers: { 'cf-connecting-ip': '198.51.100.1' /* spoofed */ },
    });
    const resolved = resolveClientIp(r, {
      trustCloudflare: true,
      trustedPeers: ['10.0.0.0/8', '192.168.1.5'],
    });
    expect(resolved).not.toBe('198.51.100.1');
    // Falls back to the raw peer address instead — mirrors fidash's
    // get_client_ip, which returns request.client.host unchanged.
    expect(resolved).toBe('203.0.113.66');
  });

  it('honors Cf-Connecting-Ip from a loopback (IPv4) peer', () => {
    const r = reqWithSocket({
      remoteAddress: '127.0.0.1',
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    expect(resolveClientIp(r, { trustCloudflare: true, trustedPeers: [] })).toBe('198.51.100.1');
  });

  it('honors Cf-Connecting-Ip from a loopback (IPv6 ::1) peer', () => {
    const r = reqWithSocket({
      remoteAddress: '::1',
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    expect(resolveClientIp(r, { trustCloudflare: true, trustedPeers: [] })).toBe('198.51.100.1');
  });

  it('honors the header from a peer inside a configured CIDR block', () => {
    const r = reqWithSocket({
      remoteAddress: '10.4.5.6',
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    expect(
      resolveClientIp(r, { trustCloudflare: true, trustedPeers: ['10.0.0.0/8'] }),
    ).toBe('198.51.100.1');
  });

  it('honors the header from a peer matching an exact-IP entry', () => {
    const r = reqWithSocket({
      remoteAddress: '192.168.1.5',
      headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.7' },
    });
    expect(
      resolveClientIp(r, { trustXff: true, trustedPeers: ['192.168.1.5'] }),
    ).toBe('203.0.113.7');
  });

  it('rejects a peer just outside the configured CIDR block', () => {
    const r = reqWithSocket({
      remoteAddress: '11.0.0.1',
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    const resolved = resolveClientIp(r, { trustCloudflare: true, trustedPeers: ['10.0.0.0/8'] });
    expect(resolved).not.toBe('198.51.100.1');
    expect(resolved).toBe('11.0.0.1');
  });

  it('degrades to "" (never throws) when trustedPeers is engaged but the socket is absent', () => {
    const r = reqWithSocket({
      remoteAddress: undefined,
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    expect(() => resolveClientIp(r, { trustCloudflare: true, trustedPeers: [] })).not.toThrow();
    expect(resolveClientIp(r, { trustCloudflare: true, trustedPeers: [] })).toBe('');
  });
});

describe('resolveClientIp: uaFallback (GAP 1 — bewks UA-fingerprint fallback)', () => {
  it('regression guard: uaFallback unset (default) falls back to req.ip, matching pre-1.5.0', () => {
    const r = req({ ip: '10.0.0.1', headers: {} });
    expect(resolveClientIp(r, { trustCloudflare: true })).toBe('10.0.0.1');
  });

  it('ADVERSARIAL / CANARY-ADJACENT: engages only when no trusted IP is available — mirrors bewks getClientId', () => {
    // bewks: cf-connecting-ip ABSENT -> untrusted -> `untrusted:<ua>`.
    const r = req({
      ip: '10.0.0.1',
      headers: { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SomeExtraJunk' },
    });
    const resolved = resolveClientIp(r, { trustCloudflare: true, uaFallback: true });
    expect(resolved).toBe(
      `untrusted:${'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SomeExtraJunk'.slice(0, 40)}`,
    );
    expect(resolved.length).toBeLessThanOrEqual(64);
  });

  it('does NOT engage when a trusted IP (Cf-Connecting-Ip) IS available — mirrors bewks trusted branch', () => {
    const r = req({
      headers: {
        'cf-connecting-ip': '198.51.100.1',
        'user-agent': 'some-ua',
      },
    });
    expect(resolveClientIp(r, { trustCloudflare: true, uaFallback: true })).toBe('198.51.100.1');
  });

  it('falls back to "untrusted:no-ua" when the User-Agent header is absent, matching bewks exactly', () => {
    const r = req({ headers: {} });
    expect(resolveClientIp(r, { trustCloudflare: true, uaFallback: true })).toBe('untrusted:no-ua');
  });

  it('truncates the User-Agent to 40 chars, matching bewks\'s userAgent.slice(0, 40)', () => {
    const ua = 'A'.repeat(100);
    const r = req({ headers: { 'user-agent': ua } });
    const resolved = resolveClientIp(r, { trustCloudflare: true, uaFallback: true });
    expect(resolved).toBe(`untrusted:${'A'.repeat(40)}`);
  });

  it('engages ahead of the peer-gate raw-peer fallback when both options are set and no trusted IP is found', () => {
    const r = reqWithSocket({
      remoteAddress: '203.0.113.66',
      headers: { 'cf-connecting-ip': '198.51.100.1' /* spoofed, untrusted peer */, 'user-agent': 'ua-x' },
    });
    const resolved = resolveClientIp(r, {
      trustCloudflare: true,
      trustedPeers: ['10.0.0.0/8'],
      uaFallback: true,
    });
    expect(resolved).toBe('untrusted:ua-x');
  });
});
