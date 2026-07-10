# Security engineering practices

Practices for doing security work in services that consume this kit — the
review method, recurring design rulings, and verification discipline. This is
the **how**; it complements [`SECURITY.md`](../SECURITY.md), which documents
this kit's **machinery**.

Distilled from a security-assurance program on a production app: a threat-model
review that turned into roughly fourteen shipped fixes. Every practice below
was validated (or learned the hard way) in that review.

---

## The review method

Model before you hunt. Enumerate **assets** (ranked by harm if
disclosed/altered/destroyed), **actors** and their trust level, the **trust
boundaries** between them, and the **abuse cases** each boundary must answer.
Bugs found without that frame tend to be a pile of unrelated symptoms; bugs
found against it are a map.

- **Findings are evidence-backed, not speculative.** A finding cites the code
  and a concrete reproduction (or a runnable check). "This looks unsafe" is a
  question, not a finding.
- **Confirmed findings become scoped tickets.** The review does not bundle
  fixes; each remediation is its own implementation ticket with acceptance
  criteria and a test. This keeps the review honest (it can't hide a fix inside
  a "review") and keeps the fixes reviewable.
- **The threat model is a living document.** Every control cites the code that
  implements it **and the test that proves it**. A control with no test is a
  convention, not a guarantee — mark it as such. When a control changes, the
  doc changes in the same PR.
- **Accepted risks are written down, not silent.** An accepted risk gets a
  table row: the risk, the rationale, who accepted it, and the **revisit
  condition** that would reopen it. Silence reads as "handled" when it isn't.

## The delivery workflow

`plan → vet → implement → review → verify → merge`, and the vet/review steps
use a **different model (or reviewer)** than the implementer.

- **Plan** holds the judgment (design, sequencing, trade-offs).
- **Vet the plan adversarially** before any code. A second model, told to attack
  the plan, repeatedly killed load-bearing assumptions ("this claim rule is
  defeated by an unverified email change", "this mount guard would 403 valid
  requests") that would have shipped as bugs.
- **Implement in small, scoped steps.** Narrow tasks return fast, fail cheap,
  and keep you in the loop. Long autonomous runs drift.
- **Review the diff adversarially.** A different model again. This catches bugs
  that look obviously correct — *including bugs in the fix for an earlier
  finding* (a claim-race that deleted the winner's session; a "transition"
  key-acceptance that never expired; a new audit trail that skipped the OAuth
  path). Cross-model disagreement is the point.
- **Verify by exercising the change**, then merge via PR. Never commit to
  `main`/`master`.

## Verification discipline

The expensive lessons. Most of these are about **not trusting a green check**.

- **Mutation-test every security guard.** Break the guard, run its test, confirm
  the test fails; then restore. A guard whose test still passes when the guard
  is neutered proves nothing. Do this for the guard *and* for the regression
  test of each fix (a regression test must fail without the fix, or it's
  decorative).
- **Re-verify every delegated claim.** "Tests pass", "already passing",
  "pre-existing failure", "not caused by my change" — whether it comes from a
  coding agent or a hurried teammate, re-run and re-baseline yourself. Agents
  in particular produce correct code but unreliable conclusions.
- **Baseline "pre-existing" against a real clean checkout**, not an in-place
  stash (a stash can no-op and compare a branch against itself). A flaky suite
  that fails a *different* test each run — and still fails when serialized — is
  environmental, not your change; characterize it before blaming yourself (or
  being blamed).
- **A control isn't done until it's verified live.** "Registration is closed"
  means `GET /api/config` returns it closed on prod, not that the fix merged.

## Design rulings

Recurring decisions, resolved once here.

- **Fail closed.** A control that gates auth, account creation, or data exposure
  is enabled only by an **exact affirmative** value; absent, empty, mis-cased,
  or differently-serialized inputs deny. Prefer `value === 'true'` over
  `value !== 'false'` — the latter treats every unanticipated input as
  permission. The deciding predicate lives in **exactly one place** per system;
  a rule duplicated across call sites is one edit from disagreeing with itself.
- **Don't boot-fail a deploy for a secure-by-fallback control.** If an absent
  config is still secure (e.g. a dedicated signing key that falls back to
  another high-entropy key), **warn** and continue — refusing to start turns a
  hardening step into an outage. Boot-fail only when absence is *insecure*
  (fail-open), not merely un-separated.
- **Session-bind token confirmations.** A bare token that performs an action on
  the token-holder's account is a confused-deputy vector: an attacker requests
  the action, then gets the victim to open the link. Require the token to belong
  to the authenticated caller.
- **Compare-and-swap for claim / rotation races.** Re-assert the preconditions
  you read (still unclaimed, still unexpired) **at the write**, inside the
  transaction — not only at the read. A lost CAS must produce **no side
  effects** (order the transaction so a lost swap commits nothing; a callback
  that returns without throwing still commits in most ORMs).
- **Anti-enumeration is a property of the response, not the log.** The audit
  trail may record whether an account existed; the caller's response must be
  byte-identical either way.
- **No permanent dual-key acceptance.** A transition that accepts an old key
  "during the window" accepts it *forever* unless each item carries an issuance
  time to bound it. If the artifact is short-lived and re-minted on read, just
  switch keys — the old ones age out on their own. Permanent acceptance of a
  retired key defeats the rotation.
- **Scope by resolved ID, not the user-facing key.** Compare against the ID the
  auth layer already resolved (`req.projectId`), not a human key that can
  collide across tenants. The predicate stays synchronous and unambiguous.
- **Enforcement completeness needs a tripwire.** A per-mount guard is one
  forgotten mount from a hole. Back it with a structural test that enumerates
  the mounts and **fails when a new one lacks the guard** — classify a mount by
  its compiled *shape*, not a parameter name a future author can vary.
- **Cap attacker-controlled input before it's stored/indexed.** Format
  validation (`.email()`) is not length validation; bound anything that lands in
  an indexed column.

## Shared-package discipline (upstream-first)

- Fix a gap in a shared kit **in the kit** — tag a release, consume it by
  version. Don't fork the mechanic into one service.
- The cleanest upstream-first is when the kit *already* ships the mechanism and
  the service just adopts it (e.g. API-key scoping was `requireScope` +
  `SecurityContext`, already in the kit, previously unused — no kit change
  needed).
- **Machinery in the kit; policy in the service.** The kit runs the guard; the
  service supplies the predicate, the secrets, and what's auditable.

## Deploy & ops safety

- **Back up the DB before migrations**, especially where automated backup isn't
  wired yet (use the engine's online backup — e.g. SQLite `.backup` — not a raw
  copy of a live file).
- **Secrets go in the env file the process actually loads.** Verify which one
  (`dotenv/config` reads from the process CWD; a pm2 `env` block is often an
  allowlist that won't pass a new var). Restart with the reload semantics that
  re-read it.
- **Restrictive file permissions belong in the deploy path**, so they persist
  across deploys — not a one-off `chmod` that the next `prisma migrate` undoes
  under the service umask.
- **Investigate blast radius before a host-wide change.** A default-deny
  firewall on a multi-service box affects *every* service on it, not the one you
  came for — enumerate the listeners first. On a single-owner box where every
  service binds all interfaces by design and the network is trusted, "harden
  one port with a firewall" is often inconsistent and low-value; prefer a
  targeted bind or an accepted-risk entry.

## Concrete patterns proven in review

Patterns that came out of the review as shipped, tested fixes:

- **Fail-closed setting with one predicate** — an auth-gating flag enabled only
  by an exact affirmative value, decided in exactly one place.
- **OAuth account-adoption defense** — resolve by provider id, refuse to adopt
  an existing password account, claim only a no-password placeholder (with
  hygiene on the claim).
- **CORS deny-by-default** — an empty allowlist means deny (not allow-all), and
  absence doesn't boot-fail a same-origin app.
- **Structural mount-coverage tripwire** — a test that enumerates route mounts
  and fails when a new one lacks the required guard.
- **Stored-XSS invariant pinned by a tripwire** — the sanitizer has a single
  importer, enforced by a dependency test so a bypass can't creep in.
- **Rate-limit ordering** — the baseline limiter mounts before the auth routes
  so nothing bypasses it.
- **Session-bound email-change confirmation** — token must belong to the
  authenticated caller, with CAS at the write and pre-write validation.
- **Kit-based API-key scoping** — adopt `requireScope` + `SecurityContext`
  rather than a bespoke per-route check.
- **Always-signed webhooks** — auto-generate the secret, tag the algorithm in
  the header, rotate on clear.
- **Separated signing key with no permanent dual-accept** — switch keys and let
  short-lived artifacts age out instead of accepting the retired key forever.
- **Auth-event audit trail** — a dedicated table that records the
  unauthenticated failure too, while the client response stays
  anti-enumeration-safe.
