/**
 * Normalize an IP string for allowlist comparison.
 *
 * - Trims whitespace.
 * - Strips an IPv4-mapped IPv6 prefix (`::ffff:203.0.113.7` -> `203.0.113.7`),
 *   matched case-insensitively — a socket can report the prefix as `::FFFF:`
 *   per RFC 4291 §2.5.5.2, not just lowercase.
 * - Lowercases the result, so a bare IPv6 literal compares case-insensitively
 *   too (a superset of savoro's `normalizeIp`, which only strips the prefix).
 *
 * Deliberately NOT CIDR-aware: this is an exact-match normalizer for an
 * exact-match allowlist (see {@link ApiKeyRecord.allowedIps}) — same scope as
 * savoro's version, just correct for the mixed-case prefix case.
 *
 * Never throws: a non-string or empty input normalizes to `''`, which only
 * matches an allowlist entry that itself normalizes to `''` (fail closed —
 * an absent/malformed `req.ip` is denied unless `''` is explicitly listed).
 */
export declare function normalizeIp(ip: string | undefined | null): string;
