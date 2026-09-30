---
kind: fixed
summary: MemoryRateLimitStore evicts idle buckets on its own clock, so an injected or pinned limiter clock no longer resets counters
---

`MemoryRateLimitStore` stamped each bucket's last-touch time with the `now` passed to `hit` (the limiter's clock, injectable for tests) but evicted stale buckets against the real `Date.now()`. With a pinned or skewed limiter clock, the first cleanup tick wiped every bucket and silently reset its counter. Idle-bucket eviction now uses one clock, the store's own: a new `now` option that defaults to `Date.now`. Window math still uses the `now` passed to `hit`. Behaviour with the default `Date.now` clock is unchanged.
