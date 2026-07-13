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

// savoro's hand-rolled normalizeIp mapped the IPv6 loopback to the v4 one. An
// earlier cut of THIS function did not — while its doc comment claimed to be a
// superset of savoro's. Adopting it would have silently started DENYING a key
// allowlisted as 127.0.0.1 whenever the socket reported ::1. The kit must be a
// superset of the code it replaces, so the loopback mapping lives here now.
describe('IPv6 loopback is canonicalized to the v4 loopback (savoro parity)', () => {
  it('maps ::1 to 127.0.0.1', () => {
    expect(normalizeIp('::1')).toBe('127.0.0.1');
  });

  it('maps the long-form IPv6 loopback to 127.0.0.1', () => {
    expect(normalizeIp('0:0:0:0:0:0:0:1')).toBe('127.0.0.1');
  });

  it('leaves the v4 loopback alone', () => {
    expect(normalizeIp('127.0.0.1')).toBe('127.0.0.1');
  });

  it('so an allowlist entry of 127.0.0.1 matches a request from ::1', () => {
    expect(normalizeIp('::1')).toBe(normalizeIp('127.0.0.1'));
  });
});
