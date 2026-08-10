---
kind: security
summary: MemoryNonceStore now reserves capacity before inserting, so a rejected nonce no longer grows the store past maxTrackedNonces.
---

`MemoryNonceStore` inserted a nonce before checking its capacity, so the
over-cap entry survived the resulting throw and every subsequent unique nonce
grew the map further — the store leaked without bound under exactly the
condition its documented cap claimed to guard. Capacity is now reserved before
insertion (still pruning expired entries first), so a rejected nonce leaves the
store untouched. The "never evict a live nonce" guarantee and the effective
maximum are unchanged.

`maxTrackedNonces` must now be a positive **integer**. A fractional value was
previously accepted and would admit `ceil(cap)` entries under the new
reservation check, which is more than the configured number reads as allowing.
