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
  if (!existsSync(join(pkgRoot, 'dist', 'core', 'signing', 'nonce-redis.d.ts'))) {
    fail('dist/core/signing/nonce-redis.d.ts is missing after build');
  }
  if (!existsSync(join(pkgRoot, 'dist', 'core', 'cors', 'policy.d.ts'))) {
    fail('dist/core/cors/policy.d.ts is missing after build');
  }
  if (!existsSync(join(pkgRoot, 'dist', 'express', 'cors', 'corsOptions.d.ts'))) {
    fail('dist/express/cors/corsOptions.d.ts is missing after build');
  }
  if (!existsSync(join(pkgRoot, 'dist', 'core', 'webhook', 'verify.d.ts'))) {
    fail('dist/core/webhook/verify.d.ts is missing after build');
  }
  if (!existsSync(join(pkgRoot, 'dist', 'express', 'webhook', 'createWebhookVerifier.d.ts'))) {
    fail('dist/express/webhook/createWebhookVerifier.d.ts is missing after build');
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
  if (!contents.includes('package/dist/core/signing/nonce-redis.d.ts')) {
    fail('dist/core/signing/nonce-redis.d.ts is not present in the packed tarball');
  }
  if (!contents.includes('package/dist/core/cors/policy.d.ts')) {
    fail('dist/core/cors/policy.d.ts is not present in the packed tarball');
  }
  if (!contents.includes('package/dist/express/cors/corsOptions.d.ts')) {
    fail('dist/express/cors/corsOptions.d.ts is not present in the packed tarball');
  }
  if (!contents.includes('package/dist/core/webhook/verify.d.ts')) {
    fail('dist/core/webhook/verify.d.ts is not present in the packed tarball');
  }
  if (!contents.includes('package/dist/express/webhook/createWebhookVerifier.d.ts')) {
    fail('dist/express/webhook/createWebhookVerifier.d.ts is not present in the packed tarball');
  }
  console.log(
    '[verify:pack] OK: dist/index.d.ts, dist/core/index.d.ts, ' +
      'dist/core/signing/nonce-redis.d.ts, dist/core/cors/policy.d.ts, ' +
      'dist/express/cors/corsOptions.d.ts, dist/core/webhook/verify.d.ts, and ' +
      'dist/express/webhook/createWebhookVerifier.d.ts ship in tarball',
  );

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
      'ipKey', 'verifiedIdentityKey', 'defaultKeyGenerator', 'decodedJwtKey',
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
    // Nonce-redis subpath export resolves.
    const nonceRedis = require('${pkg.name}/nonce-redis');
    if (typeof nonceRedis.RedisNonceStore !== 'function') {
      console.error('CJS: nonce-redis subpath missing RedisNonceStore');
      process.exit(7);
    }
    // Redis nonce store must NOT leak from the main entry.
    if ('RedisNonceStore' in mod) {
      console.error('CJS: RedisNonceStore should not be exported from main entry');
      process.exit(8);
    }
    // './core' subpath: the framework-agnostic surface.
    const core = require('${pkg.name}/core');
    const coreMissing = [
      'verifyApiKey', 'extractRawKey', 'sha256Hasher', 'scopedHmacHasher',
      'timingSafeEqualHex', 'MemoryRateLimitStore', 'ipKey', 'verifiedIdentityKey',
      'defaultKeyGenerator', 'decodedJwtKey', 'buildCanonicalString', 'signRequest',
      'sha256Hex', 'MemoryNonceStore', 'AuditBuffer', 'buildAuditEvent',
      'ConsoleAuditSink', 'auditFailureHook', 'auditRateLimitHook', 'auditDeniedHook',
      'buildDefaultContext',
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
    // Redis nonce store must NOT leak from './core' either.
    if ('RedisNonceStore' in core) {
      console.error('CJS: RedisNonceStore should not be exported from ./core');
      process.exit(9);
    }
    // './cors' subpath: framework-agnostic origin policy. This consumer never
    // installed the 'cors' npm package (only 'express' + 'helmet' peers below)
    // — proving core CORS loads fine with the 'cors' peer absent.
    const cors = require('${pkg.name}/cors');
    if (typeof cors.resolveCorsPolicy !== 'function') {
      console.error('CJS: ./cors subpath missing resolveCorsPolicy');
      process.exit(10);
    }
    // resolveCorsPolicy must NOT leak from the main entry or './core'.
    if ('resolveCorsPolicy' in mod) {
      console.error('CJS: resolveCorsPolicy should not be exported from main entry');
      process.exit(11);
    }
    if ('resolveCorsPolicy' in core) {
      console.error('CJS: resolveCorsPolicy should not be exported from ./core');
      process.exit(12);
    }
    // './express/cors' subpath: same absent-'cors'-peer consumer — corsOptions()
    // only uses 'cors' as a TYPE, never a runtime import, so it must load too.
    const expressCors = require('${pkg.name}/express/cors');
    if (typeof expressCors.corsOptions !== 'function') {
      console.error('CJS: ./express/cors subpath missing corsOptions (with cors peer absent)');
      process.exit(13);
    }
    if ('corsOptions' in mod) {
      console.error('CJS: corsOptions should not be exported from main entry');
      process.exit(14);
    }
    // './webhook' subpath: framework-agnostic signature verifier. Same
    // absent-'cors'/'ioredis'-peer consumer — verifyWebhookSignature never
    // imports either, so it must load with no optional peers present.
    const webhook = require('${pkg.name}/webhook');
    if (typeof webhook.verifyWebhookSignature !== 'function') {
      console.error('CJS: ./webhook subpath missing verifyWebhookSignature (no optional peers present)');
      process.exit(15);
    }
    if ('verifyWebhookSignature' in mod) {
      console.error('CJS: verifyWebhookSignature should not be exported from main entry');
      process.exit(16);
    }
    if ('verifyWebhookSignature' in core) {
      console.error('CJS: verifyWebhookSignature should not be exported from ./core');
      process.exit(17);
    }
    // './express/webhook' subpath: the middleware wrapper.
    const expressWebhook = require('${pkg.name}/express/webhook');
    if (typeof expressWebhook.createWebhookVerifier !== 'function') {
      console.error('CJS: ./express/webhook subpath missing createWebhookVerifier');
      process.exit(18);
    }
    if ('createWebhookVerifier' in mod) {
      console.error('CJS: createWebhookVerifier should not be exported from main entry');
      process.exit(19);
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
      ipKey as rootIpKey, verifiedIdentityKey as rootVerifiedIdentityKey,
      defaultKeyGenerator as rootDefaultKeyGenerator, decodedJwtKey as rootDecodedJwtKey,
    } from '${pkg.name}';
    import * as rootMod from '${pkg.name}';
    import { RedisRateLimitStore } from '${pkg.name}/redis-store';
    import { RedisNonceStore } from '${pkg.name}/nonce-redis';
    import { resolveCorsPolicy } from '${pkg.name}/cors';
    import { corsOptions } from '${pkg.name}/express/cors';
    import { verifyWebhookSignature } from '${pkg.name}/webhook';
    import { createWebhookVerifier } from '${pkg.name}/express/webhook';
    import {
      verifyApiKey as coreVerifyApiKey, extractRawKey, sha256Hasher as coreSha256Hasher,
      scopedHmacHasher, timingSafeEqualHex as coreTimingSafeEqualHex, MemoryRateLimitStore,
      ipKey, verifiedIdentityKey, defaultKeyGenerator, decodedJwtKey,
      buildCanonicalString as coreBuildCanonicalString, signRequest as coreSignRequest, sha256Hex,
      MemoryNonceStore as CoreMemoryNonceStore, AuditBuffer as CoreAuditBuffer,
      buildAuditEvent as coreBuildAuditEvent, ConsoleAuditSink as CoreConsoleAuditSink,
      auditFailureHook as coreAuditFailureHook, auditRateLimitHook as coreAuditRateLimitHook,
      auditDeniedHook as coreAuditDeniedHook, buildDefaultContext as coreBuildDefaultContext,
    } from '${pkg.name}/core';
    import * as coreMod from '${pkg.name}/core';
    const fns = {
      createRateLimiter, createHelmetMiddleware,
      createApiKeyAuth, verifyApiKey, requireScope, sha256Hasher, timingSafeEqualHex,
      createRequestSigningVerifier, signRequest, buildCanonicalString, MemoryNonceStore,
      AuditBuffer, buildAuditEvent, ConsoleAuditSink,
      auditFailureHook, auditRateLimitHook, auditDeniedHook,
      rootIpKey, rootVerifiedIdentityKey, rootDefaultKeyGenerator, rootDecodedJwtKey,
      coreVerifyApiKey, extractRawKey, coreSha256Hasher, scopedHmacHasher,
      coreTimingSafeEqualHex, MemoryRateLimitStore, ipKey, verifiedIdentityKey,
      defaultKeyGenerator, decodedJwtKey, coreBuildCanonicalString, coreSignRequest, sha256Hex,
      CoreMemoryNonceStore, CoreAuditBuffer, coreBuildAuditEvent, CoreConsoleAuditSink,
      coreAuditFailureHook, coreAuditRateLimitHook, coreAuditDeniedHook, coreBuildDefaultContext,
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
    if (typeof RedisNonceStore !== 'function') {
      console.error('ESM: RedisNonceStore subpath import failed');
      process.exit(7);
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
    // Redis nonce store must NOT leak from either the root entry or './core'.
    if ('RedisNonceStore' in rootMod) {
      console.error('ESM: RedisNonceStore should not be exported from main entry');
      process.exit(8);
    }
    if ('RedisNonceStore' in coreMod) {
      console.error('ESM: RedisNonceStore should not be exported from ./core');
      process.exit(9);
    }
    // './cors' and './express/cors' ESM named imports resolve — with the
    // 'cors' npm package absent from this consumer, proving core CORS (and,
    // since corsOptions() only uses 'cors' as a type, the express wrapper
    // too) load fine without the optional peer installed.
    if (typeof resolveCorsPolicy !== 'function') {
      console.error('ESM: resolveCorsPolicy subpath import failed (cors peer absent)');
      process.exit(10);
    }
    if (typeof corsOptions !== 'function') {
      console.error('ESM: corsOptions subpath import failed (cors peer absent)');
      process.exit(13);
    }
    if ('resolveCorsPolicy' in rootMod) {
      console.error('ESM: resolveCorsPolicy should not be exported from main entry');
      process.exit(11);
    }
    if ('resolveCorsPolicy' in coreMod) {
      console.error('ESM: resolveCorsPolicy should not be exported from ./core');
      process.exit(12);
    }
    if ('corsOptions' in rootMod) {
      console.error('ESM: corsOptions should not be exported from main entry');
      process.exit(14);
    }
    // './webhook' and './express/webhook' ESM named imports resolve — same
    // absent-'cors'/'ioredis'-peer consumer, proving the pure-core verifier
    // (and the express wrapper, which only imports 'express' as a type) load
    // fine with no optional peers installed.
    if (typeof verifyWebhookSignature !== 'function') {
      console.error('ESM: verifyWebhookSignature subpath import failed (no optional peers present)');
      process.exit(15);
    }
    if (typeof createWebhookVerifier !== 'function') {
      console.error('ESM: createWebhookVerifier subpath import failed');
      process.exit(18);
    }
    if ('verifyWebhookSignature' in rootMod) {
      console.error('ESM: verifyWebhookSignature should not be exported from main entry');
      process.exit(16);
    }
    if ('verifyWebhookSignature' in coreMod) {
      console.error('ESM: verifyWebhookSignature should not be exported from ./core');
      process.exit(17);
    }
    if ('createWebhookVerifier' in rootMod) {
      console.error('ESM: createWebhookVerifier should not be exported from main entry');
      process.exit(19);
    }
    console.log('ESM OK');
  `;
  writeFileSync(join(consumerDir, 'smoke.mjs'), esmSmoke);
  const esmOut = run('node', ['smoke.mjs'], { cwd: consumerDir });
  if (!esmOut.includes('ESM OK')) fail('ESM smoke did not report OK');
  console.log('[verify:pack] OK: ESM named imports resolve');

  // 5. TypeScript consumer type-check: assert the ambient Express
  //    augmentation (req.securityContext / req.rawBody) is visible to a
  //    consumer that imports the ROOT package, and that the introspection
  //    surfaces (verifyApiKey, auditFailureHook) stay pinned to express
  //    `Request` rather than the generic `SecurityRequest`.
  console.log('[verify:pack] Installing TypeScript + express types into consumer...');
  run(
    'npm',
    ['install', '--no-audit', '--no-fund', '--save-dev', 'typescript', '@types/express'],
    { cwd: consumerDir, stdio: 'inherit' },
  );

  const tsFixture = `
    import '${pkg.name}';
    import { verifyApiKey, auditFailureHook } from '${pkg.name}';
    import type { Request } from 'express';

    declare const req: Request;

    // Ambient augmentation: securityContext / rawBody must be visible on
    // express.Request once the root package is imported.
    const principalId: string | undefined = req.securityContext?.principalId;
    const rawBody: string | Buffer | undefined = req.rawBody;
    void principalId;
    void rawBody;

    // Introspection stays Request-pinned: these param types must be
    // assignable from a plain express.Request.
    type VerifyApiKeyReqParam = Parameters<typeof verifyApiKey>[1];
    type AuditFailureReqParam = Parameters<ReturnType<typeof auditFailureHook>>[0];
    const asVerifyApiKeyReq: VerifyApiKeyReqParam = req;
    const asAuditFailureReq: AuditFailureReqParam = req;
    void asVerifyApiKeyReq;
    void asAuditFailureReq;
  `;
  writeFileSync(join(consumerDir, 'fixture.ts'), tsFixture);

  const tsconfig = {
    compilerOptions: {
      strict: true,
      module: 'node16',
      moduleResolution: 'node16',
      target: 'es2022',
      skipLibCheck: false,
      noEmit: true,
    },
    include: ['fixture.ts'],
  };
  writeFileSync(join(consumerDir, 'tsconfig.json'), JSON.stringify(tsconfig, null, 2));

  console.log('[verify:pack] Type-checking consumer fixture against packed types...');
  const tscBin = join(consumerDir, 'node_modules', '.bin', 'tsc');
  try {
    run(tscBin, ['-p', 'tsconfig.json'], { cwd: consumerDir });
  } catch (err) {
    const output = [err.stdout, err.stderr].filter(Boolean).join('\n');
    fail(`consumer TypeScript compile failed:\n${output}`);
  }
  console.log(
    '[verify:pack] OK: consumer TypeScript compile succeeds ' +
      '(ambient augmentation + Request-pinned introspection)',
  );

  console.log('\n[verify:pack] PASS: all checks green');
} finally {
  try {
    rmSync(workDir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}
