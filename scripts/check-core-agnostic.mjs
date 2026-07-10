#!/usr/bin/env node
/**
 * Guard: fail if any production source file under src/core/ imports `express`
 * or `fastify` — as a value import, a `import type`, or a `require()`. This is
 * the invariant that keeps src/core/ framework-agnostic (see carve-plan.md).
 *
 * Test files (__tests__ dirs, *.test.ts) are exempt: they may reference the
 * Express `Request` type as a convenient concrete stand-in for `SecurityRequest`
 * in test fixtures without violating the "core ships express-free" guarantee,
 * since __tests__ are excluded from the tsc build (see tsconfig.json) and are
 * never shipped in dist/.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const pkgRoot = new URL('..', import.meta.url).pathname;
const coreRoot = join(pkgRoot, 'src', 'core');

// Matches every static import form that pulls the framework into the module
// graph: `from 'express'`, `require('express')` (incl. `import x = require(...)`),
// dynamic `import('express')`, and a bare side-effect `import 'express'` — with
// or without `import type`, and with or without a subpath. Computed specifiers
// (`await import(varHoldingName)`) cannot be regex-detected; the guard's
// guarantee is explicitly limited to literal string specifiers.
const FORBIDDEN_IMPORT =
  /(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"](express|fastify)(?:\/[^'"]*)?['"]/g;

function isTestFile(path) {
  return path.includes(`${join('__tests__')}${'/'}`) || /\.test\.ts$/.test(path);
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
}

if (violations.length > 0) {
  console.error('\n[check-core-agnostic] FAIL: src/core/ must never import express or fastify.\n');
  for (const { file, match } of violations) {
    console.error(`  ${file}: ${match.trim()}`);
  }
  console.error('');
  process.exit(1);
}

console.log('[check-core-agnostic] OK: no express/fastify imports under src/core/');
