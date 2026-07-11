import { describe, it, expect, vi } from 'vitest';
import { normalizeOrigin, resolveCorsPolicy } from '../policy';

describe('resolveCorsPolicy — prod fail-closed', () => {
  it('throws when production has no configured origins at all', () => {
    expect(() => resolveCorsPolicy({ env: 'production' })).toThrow(/empty allowlist|no CORS origins/i);
  });

  it('throws when production resolves an empty allowlist even with devDefaults set (dev overlays are ignored in prod)', () => {
    expect(() =>
      resolveCorsPolicy({
        env: 'production',
        devDefaults: ['http://localhost:3000'],
      }),
    ).toThrow();
  });

  it('does NOT throw in non-production with an empty allowlist', () => {
    expect(() => resolveCorsPolicy({ env: 'development' })).not.toThrow();
    expect(() => resolveCorsPolicy({ env: undefined })).not.toThrow();
  });
});

describe('resolveCorsPolicy — production allows only the listed origins', () => {
  const policy = resolveCorsPolicy({
    env: 'production',
    origins: ['https://app.example.com'],
    originsCsv: 'https://api.example.com,https://admin.example.com',
  });

  it('allows an exact-match listed origin', () => {
    expect(policy.allow('https://app.example.com')).toBe(true);
    expect(policy.allow('https://api.example.com')).toBe(true);
    expect(policy.allow('https://admin.example.com')).toBe(true);
  });

  it('denies an unlisted origin', () => {
    expect(policy.allow('https://evil.com')).toBe(false);
  });

  it('never reflects an arbitrary origin back as allowed', () => {
    const attacker = 'https://attacker-controlled-' + Math.random().toString(36).slice(2) + '.com';
    expect(policy.allow(attacker)).toBe(false);
  });

  it('never allows "*"', () => {
    expect(policy.origins).not.toContain('*');
    expect(policy.allow('*')).toBe(false);
  });
});

describe('resolveCorsPolicy — exact-match only (no subdomain/suffix matching)', () => {
  const policy = resolveCorsPolicy({
    env: 'production',
    origins: ['https://example.com'],
  });

  it('denies a subdomain of a listed origin', () => {
    expect(policy.allow('https://evil.example.com')).toBe(false);
  });

  it('denies a suffix-matching but distinct host', () => {
    expect(policy.allow('https://notexample.com')).toBe(false);
    expect(policy.allow('https://example.com.evil.com')).toBe(false);
  });
});

describe('resolveCorsPolicy — dev overlays', () => {
  it('merges devDefaults with configured origins outside production, de-duplicated', () => {
    const policy = resolveCorsPolicy({
      env: 'development',
      origins: ['https://app.example.com', 'http://localhost:3000'],
      devDefaults: ['http://localhost:3000', 'http://localhost:5173'],
    });
    expect(policy.allow('http://localhost:3000')).toBe(true);
    expect(policy.allow('http://localhost:5173')).toBe(true);
    expect(policy.allow('https://app.example.com')).toBe(true);
    // de-duped: localhost:3000 configured via both origins and devDefaults
    expect(policy.origins.filter((o) => o === 'http://localhost:3000')).toHaveLength(1);
  });

  it('ignores devDefaults entirely in production', () => {
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      devDefaults: ['http://localhost:3000'],
    });
    expect(policy.allow('http://localhost:3000')).toBe(false);
  });
});

describe('normalizeOrigin', () => {
  it('strips the default https port', () => {
    expect(normalizeOrigin('https://example.com:443')).toBe('https://example.com');
  });

  it('strips the default http port', () => {
    expect(normalizeOrigin('http://example.com:80')).toBe('http://example.com');
  });

  it('keeps a non-default port', () => {
    expect(normalizeOrigin('http://localhost:3000')).toBe('http://localhost:3000');
  });

  it('strips path/query/hash', () => {
    expect(normalizeOrigin('https://example.com/some/path?x=1#y')).toBe('https://example.com');
  });

  it('strips a trailing slash', () => {
    expect(normalizeOrigin('https://example.com/')).toBe('https://example.com');
  });

  it('lowercases the host', () => {
    expect(normalizeOrigin('https://EXAMPLE.com')).toBe('https://example.com');
  });

  it('preserves the literal "null" origin as-is', () => {
    expect(normalizeOrigin('null')).toBe('null');
  });

  it('strips credentials from a credential-bearing URL', () => {
    expect(normalizeOrigin('https://user:pass@example.com')).toBe('https://example.com');
  });

  it('throws on an invalid URL', () => {
    expect(() => normalizeOrigin('not a url')).toThrow();
  });

  it('treats an empty/whitespace-only value as absent (returns null)', () => {
    expect(normalizeOrigin('   ')).toBeNull();
    expect(normalizeOrigin('')).toBeNull();
  });
});

describe('resolveCorsPolicy — invalid configured origin throws at construction', () => {
  it('throws immediately for an unparseable configured origin (origins array)', () => {
    expect(() =>
      resolveCorsPolicy({ env: 'development', origins: ['not a url'] }),
    ).toThrow();
  });

  it('throws immediately for an unparseable configured origin (CSV)', () => {
    expect(() =>
      resolveCorsPolicy({ env: 'development', originsCsv: 'https://ok.com,not a url' }),
    ).toThrow();
  });

  it('throws immediately for an unparseable devDefaults origin', () => {
    expect(() =>
      resolveCorsPolicy({ env: 'development', devDefaults: ['not a url'] }),
    ).toThrow();
  });
});

describe('resolveCorsPolicy — allowNoOrigin', () => {
  it('default true: an undefined origin (curl / server-to-server) is allowed', () => {
    const policy = resolveCorsPolicy({ env: 'production', origins: ['https://app.example.com'] });
    expect(policy.allowNoOrigin).toBe(true);
    expect(policy.allow(undefined)).toBe(true);
  });

  it('allowNoOrigin: false denies an undefined origin', () => {
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      allowNoOrigin: false,
    });
    expect(policy.allow(undefined)).toBe(false);
  });
});

describe('resolveCorsPolicy — resolveAllowedOrigin (FIX 4)', () => {
  it('returns the CANONICAL normalized allowlist string for an allowed non-canonical input, not the raw input', () => {
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
    });
    // Raw input has a path + default port variance the allowlist entry does
    // not — normalization must produce the exact canonical form, not the
    // raw bytes the caller supplied.
    expect(policy.resolveAllowedOrigin('https://app.example.com:443/some/path')).toBe(
      'https://app.example.com',
    );
  });

  it('returns false for a denied origin, and still invokes onReject', () => {
    const onReject = vi.fn();
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      onReject,
    });
    expect(policy.resolveAllowedOrigin('https://evil.com')).toBe(false);
    expect(onReject).toHaveBeenCalledWith('https://evil.com');
  });

  it('returns the allowNoOrigin boolean for an undefined origin', () => {
    const allowed = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      allowNoOrigin: true,
    });
    expect(allowed.resolveAllowedOrigin(undefined)).toBe(true);

    const denied = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      allowNoOrigin: false,
    });
    expect(denied.resolveAllowedOrigin(undefined)).toBe(false);
  });

  it('never returns the raw attacker-controlled origin string, even when it happens to normalize to an allowed value', () => {
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://App.Example.com:443'],
    });
    const raw = 'https://APP.EXAMPLE.COM:443/x?y=1';
    const result = policy.resolveAllowedOrigin(raw);
    expect(result).not.toBe(raw);
    expect(result).toBe('https://app.example.com');
  });
});

describe('resolveCorsPolicy — onReject hook', () => {
  it('is called with the rejected origin on deny', () => {
    const onReject = vi.fn();
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      onReject,
    });
    expect(policy.allow('https://evil.com')).toBe(false);
    expect(onReject).toHaveBeenCalledWith('https://evil.com');
  });

  it('is NOT called when the origin is allowed', () => {
    const onReject = vi.fn();
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      onReject,
    });
    expect(policy.allow('https://app.example.com')).toBe(true);
    expect(onReject).not.toHaveBeenCalled();
  });

  it('is NOT called for an undefined origin (allowNoOrigin path)', () => {
    const onReject = vi.fn();
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      onReject,
    });
    policy.allow(undefined);
    expect(onReject).not.toHaveBeenCalled();
  });

  it('a throwing onReject hook does not break allow() — deny still returns false, no throw escapes', () => {
    const onReject = vi.fn(() => {
      throw new Error('boom');
    });
    const policy = resolveCorsPolicy({
      env: 'production',
      origins: ['https://app.example.com'],
      onReject,
    });
    let result: boolean | undefined;
    expect(() => {
      result = policy.allow('https://evil.com');
    }).not.toThrow();
    expect(result).toBe(false);
    expect(onReject).toHaveBeenCalled();
  });
});
