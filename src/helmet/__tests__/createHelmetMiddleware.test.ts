import { describe, it, expect } from 'vitest';
import { createHelmetMiddleware } from '../createHelmetMiddleware';

/**
 * We can't easily reach helmet's internal config, so we exercise the middleware
 * against a fake req/res and parse the Content-Security-Policy header it sets.
 */
function runHelmet(
  mw: ReturnType<typeof createHelmetMiddleware>,
): Record<string, string> {
  const headers: Record<string, string> = {};
  const res = {
    setHeader(name: string, value: string) {
      headers[name.toLowerCase()] = value;
    },
    getHeader(name: string) {
      return headers[name.toLowerCase()];
    },
    removeHeader(name: string) {
      delete headers[name.toLowerCase()];
    },
  };
  const req = { method: 'GET', secure: true, headers: {} };
  // helmet middleware is synchronous for header setting.
  mw(req as never, res as never, () => undefined);
  return headers;
}

/** Parse a CSP header string into { directive: [sources...] }. */
function parseCsp(header: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const [name, ...sources] = trimmed.split(/\s+/);
    out[name] = sources;
  }
  return out;
}

function getCsp(config?: Parameters<typeof createHelmetMiddleware>[0]) {
  const headers = runHelmet(createHelmetMiddleware(config));
  const cspHeader = headers['content-security-policy'];
  expect(cspHeader, 'CSP header should be set').toBeTruthy();
  return parseCsp(cspHeader);
}

describe('createHelmetMiddleware CSP base', () => {
  it('produces the strict base for stoki ({})', () => {
    const csp = getCsp({});
    expect(csp['default-src']).toEqual(["'self'"]);
    expect(csp['script-src']).toEqual(["'self'"]);
    expect(csp['style-src']).toEqual(["'self'"]);
    expect(csp['connect-src']).toEqual(["'self'"]);
    expect(csp['font-src']).toEqual(["'self'"]);
    expect(csp['img-src']).toEqual(["'self'", 'data:', 'https:']);
    expect(csp['object-src']).toEqual(["'none'"]);
    expect(csp['frame-src']).toEqual(["'none'"]);
    expect(csp['base-uri']).toEqual(["'self'"]);
    expect(csp['form-action']).toEqual(["'self'"]);
    // worker-src is only present when extended.
    expect(csp['worker-src']).toBeUndefined();
  });

  it('sets HSTS with a 1-year default max-age', () => {
    const headers = runHelmet(createHelmetMiddleware({}));
    const hsts = headers['strict-transport-security'];
    expect(hsts).toContain('max-age=31536000');
    expect(hsts).toContain('includeSubDomains');
    expect(hsts).toContain('preload');
  });

  it('honors a custom hstsMaxAge', () => {
    const headers = runHelmet(createHelmetMiddleware({ hstsMaxAge: 60 }));
    expect(headers['strict-transport-security']).toContain('max-age=60');
  });
});

describe('createHelmetMiddleware CSP merge', () => {
  it('appends smarthome Redoc hosts while keeping the base', () => {
    const csp = getCsp({
      csp: { scriptSrc: ['cdn.redoc.ly'], styleSrc: ['cdn.redoc.ly'] },
    });
    expect(csp['script-src']).toEqual(["'self'", 'cdn.redoc.ly']);
    expect(csp['style-src']).toEqual(["'self'", 'cdn.redoc.ly']);
    // untouched directives stay strict
    expect(csp['connect-src']).toEqual(["'self'"]);
  });

  it('appends cairn Google OAuth/Fonts hosts across directives', () => {
    const csp = getCsp({
      allowUnsafeInlineStyles: true,
      csp: {
        scriptSrc: ['https://accounts.google.com'],
        styleSrc: ['https://accounts.google.com', 'https://fonts.googleapis.com'],
        connectSrc: ['https://accounts.google.com', 'https://oauth2.googleapis.com'],
        frameSrc: ['https://accounts.google.com'],
        fontSrc: ['https://fonts.gstatic.com'],
        imgSrc: ['blob:'],
      },
    });
    expect(csp['script-src']).toEqual(["'self'", 'https://accounts.google.com']);
    expect(csp['style-src']).toEqual([
      "'self'",
      "'unsafe-inline'",
      'https://accounts.google.com',
      'https://fonts.googleapis.com',
    ]);
    expect(csp['connect-src']).toEqual([
      "'self'",
      'https://accounts.google.com',
      'https://oauth2.googleapis.com',
    ]);
    expect(csp['frame-src']).toEqual(['https://accounts.google.com']);
    expect(csp['font-src']).toEqual(["'self'", 'https://fonts.gstatic.com']);
    expect(csp['img-src']).toEqual([
      "'self'",
      'data:',
      'https:',
      'blob:',
    ]);
  });

  it('adds unsafe-inline to style-src only when allowUnsafeInlineStyles', () => {
    const off = getCsp({});
    expect(off['style-src']).not.toContain("'unsafe-inline'");
    const on = getCsp({ allowUnsafeInlineStyles: true });
    expect(on['style-src']).toContain("'unsafe-inline'");
    // scripts are never loosened
    expect(on['script-src']).not.toContain("'unsafe-inline'");
  });

  it('extends worker-src only when provided', () => {
    const csp = getCsp({ csp: { workerSrc: ['blob:'] } });
    expect(csp['worker-src']).toEqual(["'self'", 'blob:']);
  });

  it('de-duplicates repeated extra sources', () => {
    const csp = getCsp({ csp: { scriptSrc: ["'self'", 'a.com', 'a.com'] } });
    expect(csp['script-src']).toEqual(["'self'", 'a.com']);
  });
});

describe('createHelmetMiddleware overrides win last', () => {
  it('lets overrides replace a whole CSP directive', () => {
    const csp = getCsp({
      csp: { scriptSrc: ['from-preset.com'] },
      overrides: {
        contentSecurityPolicy: {
          useDefaults: false,
          directives: { scriptSrc: ["'self'", 'override.com'] },
        },
      },
    });
    // override replaces script-src entirely
    expect(csp['script-src']).toEqual(["'self'", 'override.com']);
    // other base directives survive the deep-merge
    expect(csp['default-src']).toEqual(["'self'"]);
  });

  it('lets overrides disable a helmet feature', () => {
    const headers = runHelmet(
      createHelmetMiddleware({
        overrides: { xContentTypeOptions: false },
      }),
    );
    expect(headers['x-content-type-options']).toBeUndefined();
  });
});
