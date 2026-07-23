# Releasing

Releases are deliberate and local-first: this repository has no required hosted
CI checks gating the release itself. The CHANGELOG and version bump are
produced by [`release-kit`](https://github.com/andrewpopov/release-kit) from
fragments under `.changes/unreleased/` — see `.changes/README.md` for the
fragment format.

1. **Add a fragment for each change** as it lands, via
   `npm run release:note -- --kind <kind> --slug <short-slug> --summary "User-facing summary"`
   (or by hand). `npm run release:hygiene -- --base origin/master` checks that a
   change touching `src/` (or `package.json`, `scripts/`) shipped with one.
2. **Run the full local verify battery** — every gate this repo has, in order:

   ```bash
   npm ci
   npm run typecheck          # tsc --noEmit -p tsconfig.typecheck.json, then check:core-agnostic
   npm run test
   npm run build
   npm run verify:dist-fresh  # rebuilds and diffs the committed dist/ against src/
   npm run verify:pack
   npm run audit:runtime      # npm audit --omit=dev --audit-level=high
   npm run audit:development  # npm audit --audit-level=high
   ```

   `npm run verify` chains `typecheck`, `test`, `build`, `verify:pack`,
   `audit:runtime`, and `audit:development` for you, but does **not** include
   `verify:dist-fresh` — run that separately, since it rebuilds `dist/` and
   fails if the committed output doesn't match `src/`. `check:core-agnostic`
   is not a standalone step here: it's chained onto the end of `typecheck` and
   asserts `src/core` stays framework-agnostic (no `express` imports).
3. **Cut the release:** `npm run release:cut` compiles the unreleased
   fragments into a new `## <version>` section at the top of `CHANGELOG.md`,
   bumps `package.json`, and archives the consumed fragments.
4. **Commit the result**, open the reviewed pull request, and merge it.
5. **Create the annotated tag:** `git tag -a vX.Y.Z -m vX.Y.Z` matching the
   version `release:cut` produced, and push it. The `release-guard` CI job
   checks the tag against `package.json` and the `## X.Y.Z` CHANGELOG heading.

When npm publishing is enabled, publish only from that tag with an account
protected by 2FA. Use npm provenance only after a trusted-publishing path is
configured; do not claim it otherwise. Finally, install the published package
into a clean consumer and verify its exported API before announcing the
release.
