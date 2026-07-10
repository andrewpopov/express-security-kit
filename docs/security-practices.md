# Security engineering practices

Cross-project practices for doing security work in the personal apps (Cairn,
Bewks, Savoro, Sano, FiDash, …). This is the **how** — the review method,
recurring design rulings, and verification discipline. It complements
[`SECURITY.md`](../SECURITY.md), which documents this kit's **machinery**.

Distilled from the Cairn security-assurance program (a threat-model review that
turned into ~14 shipped fixes). The worked artifacts live in the Cairn repo:
`docs/architecture/THREAT_MODEL.md` (the living model) and
`docs/architecture/REVIEW_GATES.md` (the review gates + ticket-writing rules).

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

`plan → vet → implement → review → verify → merge`, and the vet/review steps use
a **different model** than the implementer.

- **Plan** holds the judgment (design, sequencing, trade-offs).
- **Vet the plan adversarially** before any code. A second model, told to attack
  the plan, repeatedly killed load-bearing assumptions ("this claim rule is
  defeated by an unverified email change", "this mount guard would 403 valid
  requests") that would have shipped as bugs.
- **Implement in small, scoped steps.** Narrow tasks return fast, fail cheap,
  and keep the orchestrator in the loop. Long autonomous runs drift.
- **Review the diff adversarially.** A different model again. This catches bugs
  that look obviously correct — *including bugs in the fix for an earlier
  finding* (a claim-race that deleted the winner's session; a "transition"
  key-acceptance that never expired; a new audit trail that skipped the Google
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
- **Re-verify every sub-agent claim.** "Tests pass", "already passing",
  "pre-existing failure", "not caused by my change" — re-run and re-baseline
  yourself. Sub-agents produce correct code but unreliable conclusions.
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
  the service just adopts it (Cairn's API-key scoping was `requireScope` +
  `SecurityContext`, already here, previously unused — no kit change needed).
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
  came for — enumerate the listeners first. On a single-owner home server where
  every service binds all interfaces by design and the LAN is trusted, "harden
  one port with a firewall" is often inconsistent and low-value; prefer a
  targeted bind or an accepted-risk entry.

## Concrete patterns proven in review

Cross-referenced to the Cairn tickets that validated them, for the worked code.

| Pattern | Where |
| --- | --- |
| Fail-closed setting with one predicate | CAIRN-146 |
| Google/OAuth account-adoption defense (resolve by provider id, refuse to adopt a password account, claim only a no-password placeholder with hygiene) | CAIRN-151 |
| CORS deny-by-default (empty allowlist ⇒ deny, no boot-fail; same-origin app) | CAIRN-148 |
| Structural mount-coverage tripwire | CAIRN-149, CAIRN-153 |
| Stored-XSS invariant pinned by a single-importer + dependency tripwire | CAIRN-150 |
| Rate-limit ordering (baseline before the auth routes so nothing bypasses it) | CAIRN-156 |
| Session-bound email-change confirmation + CAS + pre-write validation | CAIRN-159 |
| Kit-based API-key project scoping (adopt `requireScope`) | CAIRN-153 |
| Always-signed webhooks (auto-gen secret, algorithm-tagged header, rotate-on-clear) | CAIRN-154 |
| Separated signing key with no permanent dual-accept | CAIRN-155 |
| Auth-event audit trail (dedicated table, records the unauthenticated failure, anti-enumeration preserved) | CAIRN-147 |
