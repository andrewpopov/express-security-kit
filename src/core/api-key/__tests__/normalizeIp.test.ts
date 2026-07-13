import { describe, it, expect } from 'vitest';
import { normalizeIp } from '../normalizeIp';

describe('normalizeIp', () => {
  it('strips an IPv4-mapped IPv6 prefix', () => {
    expect(normalizeIp('::ffff:203.0.113.7')).toBe('203.0.113.7');
  });

  it('strips the prefix case-insensitively', () => {
    expect(normalizeIp('::FFFF:203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeIp('::Ffff:203.0.113.7')).toBe('203.0.113.7');
  });

  it('trims whitespace', () => {
    expect(normalizeIp('  203.0.113.7  ')).toBe('203.0.113.7');
  });

  it('lowercases a plain IPv6 literal', () => {
    expect(normalizeIp('2001:DB8::1')).toBe('2001:db8::1');
  });

  it('leaves a plain IPv4 address unchanged (aside from lowercasing, a no-op)', () => {
    expect(normalizeIp('203.0.113.7')).toBe('203.0.113.7');
  });

  it('non-string / undefined / null input normalizes to empty string', () => {
    expect(normalizeIp(undefined)).toBe('');
    expect(normalizeIp(null)).toBe('');
  });

  it('never throws on garbage input', () => {
    expect(() => normalizeIp('' as string)).not.toThrow();
  });
});
