#!/usr/bin/env node
/**
 * Guard: fail if any production source file under src/core/ imports `express`,
 * `fastify`, `cors`, or `ioredis` — as a value import, a `import type`, or a
 * `require()`. This is the invariant that keeps src/core/ framework- and
 * client-agnostic (see carve-plan.md): the `cors`/`ioredis` optional peers are
 * each reachable only from their own dedicated subpath (`./express/cors`,
 * `./nonce-redis`, `./redis-store`), never from core.
 *
 * Also fails if any production source file under src/core/ has a RELATIVE
 * import/require/dynamic-import (`./...`, `../...`) that resolves OUTSIDE
 * src/core/ — e.g. reaching into src/express/. That's the same invariant as
 * the express/fastify literal check, just closing the loophole where core
 * code could sidestep it by relative-pathing into express/ instead of using
 * the bare specifier.
 *
 * Test files (__tests__ dirs, *.test.ts) are exempt: they may reference the
 * Express `Request` type as a convenient concrete stand-in for `SecurityRequest`
 * in test fixtures without violating the "core ships express-free" guarantee,
 * since __tests__ are excluded from the tsc build (see tsconfig.json) and are
 * never shipped in dist/.
 *
 * Also guards the two adapters' independence from each other: `src/fastify/`
 * must never import `express`, and `src/express/` must never import
 * `fastify` — each adapter must load standalone with the OTHER framework's
 * peer absent. Same `FORBIDDEN_IMPORT` machinery and `isTestFile` exemption
 * as the core check above.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = fileURLToPath(new URL('..', import.meta.url));
const coreRoot = join(pkgRoot, 'src', 'core');
const coreRootWithSep = coreRoot.endsWith(sep) ? coreRoot : coreRoot + sep;
const expressRoot = join(pkgRoot, 'src', 'express');
const fastifyRoot = join(pkgRoot, 'src', 'fastify');

// Matches every static import form that pulls the framework into the module
// graph: `from 'express'`, `require('express')` (incl. `import x = require(...)`),
// dynamic `import('express')`, and a bare side-effect `import 'express'` — with
// or without `import type`, and with or without a subpath. Computed specifiers
// (`await import(varHoldingName)`) cannot be regex-detected; the guard's
// guarantee is explicitly limited to literal string specifiers.
const FORBIDDEN_IMPORT =
  /(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"](express|fastify|cors|ioredis)(?:\/[^'"]*)?['"]/g;

// Same import-form coverage as FORBIDDEN_IMPORT above, but captures the
// specifier for ANY relative path (leading '.') so it can be resolved and
// checked for escaping src/core/.
const RELATIVE_IMPORT =
  /(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"](\.[^'"]*)['"]/g;

function isTestFile(path) {
  return path.includes(`${join('__tests__')}${'/'}`) || /\.test\.ts$/.test(path);
}

function findEscapingImports(file, contents) {
  const fileDir = dirname(file);
  const escapes = [];
  let match;
  while ((match = RELATIVE_IMPORT.exec(contents)) !== null) {
    const specifier = match[1];
    const resolved = resolve(fileDir, specifier);
    if (resolved !== coreRoot && !resolved.startsWith(coreRootWithSep)) {
      escapes.push({ specifier, resolved });
    }
  }
  return escapes;
}

/**
 * Full matches of FORBIDDEN_IMPORT whose captured specifier is one of
 * `forbiddenNames` — used by the adapter-independence checks below, which
 * (unlike the core check) only forbid ONE of the four names per directory.
 */
function findForbiddenImportsOf(contents, forbiddenNames) {
  const regex = new RegExp(FORBIDDEN_IMPORT.source, 'g');
  const found = [];
  let match;
  while ((match = regex.exec(contents)) !== null) {
    if (forbiddenNames.includes(match[1])) {
      found.push(match[0]);
    }
  }
  return found;
}

function walk(dir, files = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stats = statSync(full);
    if (stats.isDirectory()) {
      walk(full, files);
    } else if (entry.endsWith('.ts')) {
      files.push(full);
    }
  }
  return files;
}

const violations = [];
const escapeViolations = [];

for (const file of walk(coreRoot)) {
  const relPath = relative(pkgRoot, file);
  if (isTestFile(relPath)) continue;

  const contents = readFileSync(file, 'utf8');
  const matches = contents.match(FORBIDDEN_IMPORT);
  if (matches) {
    for (const match of matches) {
      violations.push({ file: relPath, match });
    }
  }

  for (const { specifier, resolved } of findEscapingImports(file, contents)) {
    escapeViolations.push({ file: relPath, specifier, resolved: relative(pkgRoot, resolved) });
  }
}

if (violations.length > 0) {
  console.error(
    '\n[check-core-agnostic] FAIL: src/core/ must never import express, fastify, cors, or ioredis.\n',
  );
  for (const { file, match } of violations) {
    console.error(`  ${file}: ${match.trim()}`);
  }
  console.error('');
  process.exit(1);
}

if (escapeViolations.length > 0) {
  console.error(
    '\n[check-core-agnostic] FAIL: src/core/ must never relative-import outside src/core/.\n',
  );
  for (const { file, specifier, resolved } of escapeViolations) {
    console.error(`  ${file}: '${specifier}' resolves to ${resolved}`);
  }
  console.error('');
  process.exit(1);
}

console.log('[check-core-agnostic] OK: no express/fastify/cors/ioredis imports under src/core/');
console.log('[check-core-agnostic] OK: no relative imports escape src/core/');

// Adapter independence: each adapter must load with the OTHER framework's
// peer absent, so neither may import the other's framework.
const expressImportsFastify = [];
for (const file of walk(expressRoot)) {
  const relPath = relative(pkgRoot, file);
  if (isTestFile(relPath)) continue;
  const contents = readFileSync(file, 'utf8');
  for (const match of findForbiddenImportsOf(contents, ['fastify'])) {
    expressImportsFastify.push({ file: relPath, match });
  }
}

if (expressImportsFastify.length > 0) {
  console.error('\n[check-core-agnostic] FAIL: src/express/ must never import fastify.\n');
  for (const { file, match } of expressImportsFastify) {
    console.error(`  ${file}: ${match.trim()}`);
  }
  console.error('');
  process.exit(1);
}

console.log('[check-core-agnostic] OK: no fastify imports under src/express/');

const fastifyImportsExpress = [];
for (const file of walk(fastifyRoot)) {
  const relPath = relative(pkgRoot, file);
  if (isTestFile(relPath)) continue;
  const contents = readFileSync(file, 'utf8');
  for (const match of findForbiddenImportsOf(contents, ['express'])) {
    fastifyImportsExpress.push({ file: relPath, match });
  }
}

if (fastifyImportsExpress.length > 0) {
  console.error('\n[check-core-agnostic] FAIL: src/fastify/ must never import express.\n');
  for (const { file, match } of fastifyImportsExpress) {
    console.error(`  ${file}: ${match.trim()}`);
  }
  console.error('');
  process.exit(1);
}

console.log('[check-core-agnostic] OK: no express imports under src/fastify/');
