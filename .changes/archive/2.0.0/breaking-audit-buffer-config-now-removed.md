---
kind: breaking
summary: AuditBufferConfig.now (an injectable clock) is removed: AuditBuffer never read it, so it was a documented no-op. Remove any now: () => ... you were passing to new AuditBuffer(...).
---

`AuditBuffer` has no time-dependent logic of its own — its periodic flush
uses a real `setInterval`/`setTimeout`, not a computed "now" — so `now` was
dead from the day it was added: nothing in `AuditBuffer` ever called it.
Removed rather than wired up. If you were passing `now` to `new
AuditBuffer(...)`, it had no effect and can simply be dropped; a TypeScript
consumer will see it as an unknown-property compile error. Checked against
the consuming fleet: no current consumer passes `AuditBufferConfig.now`, so
this removal has no practical impact on anyone shipping today. (Note:
`BuildAuditEventOptions.now`, used by `buildAuditEvent` to stamp each event's
timestamp, is a different, still-supported option — unaffected by this
change.)
