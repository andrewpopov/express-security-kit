#!/usr/bin/env node
/**
 * Pack the package into a tarball, install it into a throwaway project, and
 * assert that:
 *   1. dist/index.d.ts AND dist/core/index.d.ts ship inside the tarball.
 *   2. CommonJS `require()` exposes createRateLimiter + createHelmetMiddleware
 *      from the root entry, and the framework-agnostic surface from `./core`.
 *   3. Native ESM `import { ... }` resolves the same named exports (this is what
 *      catches the "member-expression export" bug where cjs-module-lexer can't
 *      see the names for ESM consumers) from BOTH the root entry and `./core`.
 *   4. Neither the root entry nor `./core` leaks `RedisRateLimitStore` — it is
 *      only reachable via the `./redis-store` subpath.
 *
 * Exits non-zero with a clear message on any failure.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const pkgRoot = new URL('..', import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', ...opts });
}

function fail(message) {
  console.error(`\n[verify:pack] FAIL: ${message}\n`);
  process.exit(1);
}

const workDir = mkdtempSync(join(tmpdir(), 'esk-verify-'));
let tarballPath;

try {
  console.log('[verify:pack] Building...');
  run('npm', ['run', 'build'], { cwd: pkgRoot, stdio: 'inherit' });

  console.log('[verify:pack] Checking core/ stays framework-agnostic...');
  run('node', ['scripts/check-core-agnostic.mjs'], { cwd: pkgRoot, stdio: 'inherit' });

  if (!existsSync(join(pkgRoot, 'dist', 'index.d.ts'))) {
    fail('dist/index.d.ts is missing after build');
  }
  if (!existsSync(join(pkgRoot, 'dist', 'core', 'index.d.ts'))) {
    fail('dist/core/index.d.ts is missing after build');
  }

  console.log('[verify:pack] Packing tarball...');
  const packOut = run('npm', ['pack', '--json', '--pack-destination', workDir], {
    cwd: pkgRoot,
  });
  const packInfo = JSON.parse(packOut);
  const filename = packInfo[0].filename;
  tarballPath = join(workDir, filename);

  // 1. Assert the declaration files ship inside the tarball.
  const contents = run('tar', ['-tzf', tarballPath]);
  if (!contents.includes('package/dist/index.d.ts')) {
    fail('dist/index.d.ts is not present in the packed tarball');
  }
  if (!contents.includes('package/dist/core/index.d.ts')) {
    fail('dist/core/index.d.ts is not present in the packed tarball');
  }
  console.log('[verify:pack] OK: dist/index.d.ts and dist/core/index.d.ts ship in tarball');

  // Set up a throwaway consumer project and install the tarball.
  const consumerDir = join(workDir, 'consumer');
  run('mkdir', ['-p', consumerDir]);
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify(
      {
        name: 'esk-consumer',
        version: '1.0.0',
        private: true,
        // Peer deps are required by the package; provide them so it loads.
      },
      null,
      2,
    ),
  );

  console.log('[verify:pack] Installing tarball + peers into consumer...');
  run('npm', ['install', '--no-audit', '--no-fund', tarballPath, 'express', 'helmet'], {
    cwd: consumerDir,
    stdio: 'inherit',
  });

  // 2. CommonJS require smoke.
  const cjsSmoke = `
    const mod = require('${pkg.name}');
    const missing = [
      'createRateLimiter', 'createHelmetMiddleware',
      'createApiKeyAuth', 'verifyApiKey', 'requireScope', 'sha256Hasher',
      'scopedHmacHasher', 'timingSafeEqualHex',
      'createRequestSigningVerifier', 'signRequest',
      'buildCanonicalString', 'MemoryNonceStore',
      'AuditBuffer', 'buildAuditEvent', 'ConsoleAuditSink',
      'auditFailureHook', 'auditRateLimitHook', 'auditDeniedHook',
    ].filter((n) => typeof mod[n] !== 'function');
    if (missing.length) {
      console.error('CJS missing exports: ' + missing.join(', '));
      process.exit(2);
    }
    // Redis store must NOT leak from the main entry.
    if ('RedisRateLimitStore' in mod) {
      console.error('CJS: RedisRateLimitStore should not be exported from main entry');
      process.exit(3);
    }
    // Subpath export resolves.
    const redis = require('${pkg.name}/redis-store');
    if (typeof redis.RedisRateLimitStore !== 'function') {
      console.error('CJS: redis-store subpath missing RedisRateLimitStore');
      process.exit(4);
    }
    // './core' subpath: the framework-agnostic surface.
    const core = require('${pkg.name}/core');
    const coreMissing = [
      'verifyApiKey', 'extractRawKey', 'sha256Hasher', 'scopedHmacHasher',
      'timingSafeEqualHex', 'MemoryRateLimitStore', 'ipKey', 'verifiedIdentityKey',
      'defaultKeyGenerator', 'decodedJwtKey', 'buildCanonicalString', 'signRequest',
      'sha256Hex', 'MemoryNonceStore', 'AuditBuffer', 'buildAuditEvent',
      'ConsoleAuditSink', 'auditFailureHook', 'auditRateLimitHook', 'auditDeniedHook',
    ].filter((n) => typeof core[n] !== 'function');
    if (coreMissing.length) {
      console.error('CJS ./core missing exports: ' + coreMissing.join(', '));
      process.exit(5);
    }
    // Redis store must NOT leak from './core' either.
    if ('RedisRateLimitStore' in core) {
      console.error('CJS: RedisRateLimitStore should not be exported from ./core');
      process.exit(6);
    }
    console.log('CJS OK');
  `;
  writeFileSync(join(consumerDir, 'smoke.cjs'), cjsSmoke);
  const cjsOut = run('node', ['smoke.cjs'], { cwd: consumerDir });
  if (!cjsOut.includes('CJS OK')) fail('CommonJS smoke did not report OK');
  console.log('[verify:pack] OK: CommonJS require exposes named exports');

  // Assert the RateLimitRejection type ships in the packed declarations.
  const dtsIndex = readFileSync(join(pkgRoot, 'dist', 'index.d.ts'), 'utf8');
  if (!dtsIndex.includes('RateLimitRejection')) {
    fail('RateLimitRejection type is not exported from dist/index.d.ts');
  }
  console.log('[verify:pack] OK: RateLimitRejection type exported');

  // Assert the RateLimitStore interface declares `decrement` (the refund hook).
  const storeDts = readFileSync(join(pkgRoot, 'dist', 'core', 'rate-limit', 'store.d.ts'), 'utf8');
  if (!/decrement\s*\(/.test(storeDts)) {
    fail('RateLimitStore.decrement is missing from dist/core/rate-limit/store.d.ts');
  }
  console.log('[verify:pack] OK: RateLimitStore.decrement declared');

  // 3. Native ESM import smoke (catches the member-expression export bug).
  const esmSmoke = `
    import {
      createRateLimiter, createHelmetMiddleware,
      createApiKeyAuth, verifyApiKey, requireScope, sha256Hasher, timingSafeEqualHex,
      createRequestSigningVerifier, signRequest, buildCanonicalString, MemoryNonceStore,
      AuditBuffer, buildAuditEvent, ConsoleAuditSink,
      auditFailureHook, auditRateLimitHook, auditDeniedHook,
    } from '${pkg.name}';
    import * as rootMod from '${pkg.name}';
    import { RedisRateLimitStore } from '${pkg.name}/redis-store';
    import {
      verifyApiKey as coreVerifyApiKey, extractRawKey, sha256Hasher as coreSha256Hasher,
      scopedHmacHasher, timingSafeEqualHex as coreTimingSafeEqualHex, MemoryRateLimitStore,
      ipKey, verifiedIdentityKey, defaultKeyGenerator, decodedJwtKey,
      buildCanonicalString as coreBuildCanonicalString, signRequest as coreSignRequest, sha256Hex,
      MemoryNonceStore as CoreMemoryNonceStore, AuditBuffer as CoreAuditBuffer,
      buildAuditEvent as coreBuildAuditEvent, ConsoleAuditSink as CoreConsoleAuditSink,
      auditFailureHook as coreAuditFailureHook, auditRateLimitHook as coreAuditRateLimitHook,
      auditDeniedHook as coreAuditDeniedHook,
    } from '${pkg.name}/core';
    import * as coreMod from '${pkg.name}/core';
    const fns = {
      createRateLimiter, createHelmetMiddleware,
      createApiKeyAuth, verifyApiKey, requireScope, sha256Hasher, timingSafeEqualHex,
      createRequestSigningVerifier, signRequest, buildCanonicalString, MemoryNonceStore,
      AuditBuffer, buildAuditEvent, ConsoleAuditSink,
      auditFailureHook, auditRateLimitHook, auditDeniedHook,
      coreVerifyApiKey, extractRawKey, coreSha256Hasher, scopedHmacHasher,
      coreTimingSafeEqualHex, MemoryRateLimitStore, ipKey, verifiedIdentityKey,
      defaultKeyGenerator, decodedJwtKey, coreBuildCanonicalString, coreSignRequest, sha256Hex,
      CoreMemoryNonceStore, CoreAuditBuffer, coreBuildAuditEvent, CoreConsoleAuditSink,
      coreAuditFailureHook, coreAuditRateLimitHook, coreAuditDeniedHook,
    };
    for (const [name, fn] of Object.entries(fns)) {
      if (typeof fn !== 'function') {
        console.error('ESM: ' + name + ' is not a function');
        process.exit(2);
      }
    }
    if (typeof RedisRateLimitStore !== 'function') {
      console.error('ESM: RedisRateLimitStore subpath import failed');
      process.exit(4);
    }
    // Redis store must NOT leak from either the root entry or './core'.
    if ('RedisRateLimitStore' in rootMod) {
      console.error('ESM: RedisRateLimitStore should not be exported from main entry');
      process.exit(3);
    }
    if ('RedisRateLimitStore' in coreMod) {
      console.error('ESM: RedisRateLimitStore should not be exported from ./core');
      process.exit(6);
    }
    console.log('ESM OK');
  `;
  writeFileSync(join(consumerDir, 'smoke.mjs'), esmSmoke);
  const esmOut = run('node', ['smoke.mjs'], { cwd: consumerDir });
  if (!esmOut.includes('ESM OK')) fail('ESM smoke did not report OK');
  console.log('[verify:pack] OK: ESM named imports resolve');

  console.log('\n[verify:pack] PASS: all checks green');
} finally {
  try {
    rmSync(workDir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}
