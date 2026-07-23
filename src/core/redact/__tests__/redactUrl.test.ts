import { describe, it, expect } from 'vitest';
import { redactUrl } from '../redactUrl';

describe('redactUrl', () => {
  it('redacts a query token on /reset-password', () => {
    expect(redactUrl('/reset-password?token=SECRET', { sensitiveParams: ['token'] })).toBe(
      '/reset-password?token=REDACTED',
    );
  });

  it('redacts a query token on /confirm-email-change', () => {
    expect(
      redactUrl('/confirm-email-change?token=SECRET', { sensitiveParams: ['token'] }),
    ).toBe('/confirm-email-change?token=REDACTED');
  });

  it('redacts a path token following an "invites" marker segment', () => {
    expect(
      redactUrl('/api/invites/SECRET', { sensitiveSegments: { afterSegments: ['invites', 'invite'] } }),
    ).toBe('/api/invites/REDACTED');
  });

  it('redacts a path token in the middle of the path (invites/<tok>/accept)', () => {
    expect(
      redactUrl('/api/invites/SECRET/accept', {
        sensitiveSegments: { afterSegments: ['invites', 'invite'] },
      }),
    ).toBe('/api/invites/REDACTED/accept');
  });

  it('redacts a path token on the SPA /invite/<tok> route', () => {
    expect(
      redactUrl('/invite/SECRET', { sensitiveSegments: { afterSegments: ['invites', 'invite'] } }),
    ).toBe('/invite/REDACTED');
  });

  it('redacts BOTH a path token and query tokens on an invite setup URL', () => {
    expect(
      redactUrl('/api/invites/SECRET/setup?token=XYZ&invite=ABC', {
        sensitiveSegments: { afterSegments: ['invites', 'invite'] },
        sensitiveParams: ['token', 'invite'],
      }),
    ).toBe('/api/invites/REDACTED/setup?token=REDACTED&invite=REDACTED');
  });

  it('preserves non-sensitive query params and their order', () => {
    expect(
      redactUrl('/api/invites/SECRET?foo=1&page=2', {
        sensitiveSegments: { afterSegments: ['invites'] },
      }),
    ).toBe('/api/invites/REDACTED?foo=1&page=2');
  });

  it('is a no-op when nothing matches', () => {
    expect(
      redactUrl('/api/lists/1?foo=1&page=2', {
        sensitiveParams: ['token'],
        sensitiveSegments: { afterSegments: ['invites'] },
      }),
    ).toBe('/api/lists/1?foo=1&page=2');
  });

  it('matches param names case-insensitively', () => {
    expect(redactUrl('/reset-password?Token=SECRET', { sensitiveParams: ['token'] })).toBe(
      '/reset-password?Token=REDACTED',
    );
  });

  it('matches marker segments case-insensitively', () => {
    expect(
      redactUrl('/Invites/SECRET', { sensitiveSegments: { afterSegments: ['invites'] } }),
    ).toBe('/Invites/REDACTED');
  });

  it('preserves a #fragment', () => {
    expect(
      redactUrl('/reset-password?token=SECRET#panel', { sensitiveParams: ['token'] }),
    ).toBe('/reset-password?token=REDACTED#panel');
  });

  it('honors a custom placeholder', () => {
    expect(
      redactUrl('/reset-password?token=SECRET', { sensitiveParams: ['token'], placeholder: '***' }),
    ).toBe('/reset-password?token=***');
  });

  it('does not throw on an empty string', () => {
    expect(() => redactUrl('')).not.toThrow();
    expect(redactUrl('')).toBe('');
  });

  it('does not throw on malformed "???" input', () => {
    expect(() => redactUrl('???')).not.toThrow();
  });

  it('does not throw on a path with no leading slash, and still redacts', () => {
    expect(() => redactUrl('invites/SECRET')).not.toThrow();
    expect(
      redactUrl('invites/SECRET', { sensitiveSegments: { afterSegments: ['invites'] } }),
    ).toBe('invites/REDACTED');
  });

  it('never throws on non-string input', () => {
    expect(() => redactUrl(null as unknown as string)).not.toThrow();
    expect(() => redactUrl(undefined as unknown as string)).not.toThrow();
  });

  // Hardening (Codex review): a percent-encoded sensitive name/marker must not
  // slip a credential past redaction just because a downstream decoder would
  // still route it as the sensitive name.
  it('redacts a percent-encoded sensitive query-param name', () => {
    expect(redactUrl('/reset?%74oken=SECRET', { sensitiveParams: ['token'] })).toBe(
      '/reset?%74oken=REDACTED',
    );
    expect(redactUrl('/reset?to%6Ben=SECRET', { sensitiveParams: ['token'] })).toBe(
      '/reset?to%6Ben=REDACTED',
    );
  });

  it('redacts the token after a percent-encoded marker segment', () => {
    expect(
      redactUrl('/api/%69nvites/SECRET', { sensitiveSegments: { afterSegments: ['invites'] } }),
    ).toBe('/api/%69nvites/REDACTED');
  });

  it('strips userinfo credentials from an absolute URL authority', () => {
    expect(redactUrl('https://alice:SECRET@example.com/reset')).toBe(
      'https://REDACTED@example.com/reset',
    );
    expect(redactUrl('https://alice@example.com/x')).toBe('https://REDACTED@example.com/x');
  });

  it('does not invent userinfo on a bare path containing an @', () => {
    // No scheme://, so the @ is just a path/query char, not authority userinfo.
    expect(redactUrl('/mentions/@alice')).toBe('/mentions/@alice');
  });
});
