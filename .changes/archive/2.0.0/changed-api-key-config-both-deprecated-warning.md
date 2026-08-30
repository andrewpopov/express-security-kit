---
kind: changed
summary: A config supplying both rawAuthenticator and lookup no longer throws: rawAuthenticator wins and lookup is ignored (unchanged), but a one-time deprecation warning is now logged, since lookup used to be REQUIRED and every canonical-path consumer was forced to supply a dead one.
---

Before this release, `lookup` was REQUIRED on `ApiKeyAuthConfigCore`, so every
canonical-path (`rawAuthenticator`) consumer had to supply a dead `lookup`
just to satisfy the type — several real services do exactly this today.
Behavior for that shape is UNCHANGED: `rawAuthenticator` still wins and
`lookup` is still silently ignored. What's new is visibility: a one-time
(per config object, not per request) deprecation warning is logged via
`config.logger` (default `console.warn`), naming the problem and pointing at
the fix — delete the now-unnecessary `lookup`. Supplying both will become a
construction-time error in a future major version; this release only
announces that, it does not enforce it. No action is required now, but
removing the dead `lookup` silences the warning and is recommended.
