# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.3.2] - 2026-04-14

### Fixed
- Hostname resolution failures and `resolves_to` check failures are now logged at the configured debug level (info when `debug: true`, debug otherwise). Previously these denials were silent — no log entry was emitted, making it impossible to distinguish a policy denial from a network or DNS error when diagnosing failed certificate requests.
- Added `dns_timeout` configuration option to control the per-query DNS timeout when `resolvers` is configured. Accepts a Go duration string (e.g. `10s`, `500ms`). Defaults to `5s`. Caddy placeholders are supported.

---

## [v1.3.1] - 2026-04-13

### Added
- `debug` configuration option. When `true`, per-request policy evaluation details (hostname normalisation, subdomain depth, allow/deny regexp and subdomain checks, `resolves_to` matches, and final allow/deny outcome) are emitted at info level regardless of the global Caddy log level. When `false` (the default), the same details are only emitted when Caddy's global log level is set to debug.

---

## [v1.3.0] - 2026-04-09

### Fixed
- `isLocalIP` now rejects global multicast addresses (224.0.0.0/4, ff00::/8). Previously only link-local multicast was checked, allowing hostnames that resolve to global multicast IPs to bypass the `permit_local: false` check.
- `parseBoolInto` now validates that a value was supplied, making the function safe to call independently of the outer empty-value guard.

### Changed
- `resolves_to` now performs CNAME-aware matching when `resolvers` is configured: the full DNS resolution chain (initial query name plus each intermediate CNAME target) is collected for both the incoming hostname and each configured target. A hostname passes if any chain element — CNAME name or final IP address — appears in the set produced by resolving the targets. This means a hostname that shares an intermediate CNAME with a target (e.g. both aliasing the same CDN hostname) passes even when their final IP addresses differ, as can happen across geo-DNS boundaries. Without `resolvers`, the system resolver is used and matching falls back to IP comparison only, as the system resolver does not expose intermediate CNAME records.
- `resolves_to` matching now uses "any chain element matches" semantics. Previously all resolved IP addresses of the incoming hostname had to be present in the target set; now a single matching element is sufficient.
- When `resolves_to` is configured, allowed target members are resolved before the incoming hostname so that CNAME name matching can short-circuit resolution of the incoming hostname as soon as a match is found, avoiding unnecessary DNS queries. The resolved members map is now threaded directly into the final `resolves_to` check, eliminating a redundant cache lookup per request.
- `max_subdomain_depth_raw` is no longer included in JSON output. It is a Caddyfile-only intermediary and has no meaning in JSON config; previously it could silently override `max_subdomain_depth` if both were set.

### Removed
- `max_certs_per_domain` configuration option and all associated approval state persistence. Certificate cap functionality is out of scope for this module.
- `rate_limit` and `per_domain_rate_limit` configuration options and all associated in-memory sliding-window counters. Issuance rate limiting is now provided by [`caddy-tls-issuer-rate-limit`](https://github.com/pberkel/caddy-tls-issuer-rate-limit), which enforces limits after `SubjectTransformer` has run (on effective certificate subjects rather than raw hostnames).

---

## [v1.2.3] - 2026-04-01

### Changed
- `resolvers` now accepts bare hostnames and IP addresses without a port. Port `53` is assumed when no port is specified, matching the behaviour of `caddy-redir-dns`.

---

## [v1.2.2] - 2026-04-01

### Changed
- Renamed the `nameserver` configuration option to `resolvers` to conform to Caddy naming conventions. The JSON field has been updated from `nameserver` to `resolvers` accordingly.
- Rewrote the Policy Options section of the README as a reference table and converted the Policy Order section to a numbered list.
- Added Apache 2.0 license banner to all source files.

---

## [v1.2.1] - 2026-03-27

### Changed
- Added Go doc comment to `PermissionByPolicy` struct.

---

## [v1.2.0] - 2026-03-27

### Fixed
- Caddyfile-configured `rate_limit`, `per_domain_rate_limit`, `max_subdomain_depth`, and `max_certs_per_domain` values were silently lost during the Caddyfile → JSON → provision round-trip because raw string fields were tagged `json:"-"` and not serialized. This caused provision errors ("limit must be greater than 0") and silent reversion to zero values. Raw fields are now exported and JSON-visible (`limit_raw`, `duration_raw`, `max_subdomain_depth_raw`, `max_certs_per_domain_raw`) with `omitempty` so they survive serialization and take precedence at provision time.

### Changed
- Removed `omitempty` from the `max_subdomain_depth` and `max_certs_per_domain` JSON tags. The value `0` is meaningful for both fields (depth 0 = apex only; 0 certs = deny all new names) and must survive JSON round-trips through the Caddy admin API.

### Added
- `rate_limit` configuration option to enforce a global rolling-window cap on certificate approvals across all domains (limit and duration).
- `per_domain_rate_limit` configuration option to enforce a per-registrable-domain rolling-window cap on certificate approvals (limit and duration).
- Rate limit checks are applied early in the policy pipeline to avoid unnecessary DNS resolution for over-limit requests.
- Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) support for `rate_limit` and `per_domain_rate_limit` limit and duration arguments.
- Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) support for `max_certs_per_domain`.
- Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) support for `max_subdomain_depth`.

---

## [v1.1.0] - 2026-03-26

### Added
- `nameserver` configuration option to specify one or more custom DNS servers (HOST:PORT) for resolving hostnames, instead of the system resolver.
- Custom DNS resolver with parallel A and AAAA record queries, CNAME chain following (up to 8 hops), and loop detection.
- Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) support for `allow_subdomain`, `deny_subdomain`, `resolves_to`, and `nameserver` configuration values.
- Validation of `max_subdomain_depth` and `max_certs_per_domain`: values below -1 are now rejected at provisioning time with a descriptive error.
- 5-minute TTL in-memory cache for resolved `resolves_to` target IP addresses, avoiding repeated DNS lookups on every certificate request.

### Changed
- Extracted Caddyfile parsing and module provisioning into a dedicated `caddyfile.go` file.
- `allow_subdomain` and `deny_subdomain` now use O(1) map lookups (built at provisioning time) instead of linear slice iteration.
- Renamed `PermitIp` field to `PermitIP` to follow Go initialism naming conventions.
- `max_certs_per_domain` and `max_subdomain_depth` now include their values in JSON output regardless of value (see v1.2.0 Changed for rationale).
- Write lock in `resolves_to` target cache refresh is no longer held during DNS I/O, preventing concurrent readers from blocking for the full DNS timeout duration.
- Updated README with corrected policy evaluation order, documented `resolves_to` caching behaviour, added missing `permit_all` option entry, and various corrections and clarifications.

### Fixed
- IPv4-in-IPv6 addresses (e.g. `::ffff:1.2.3.4`) returned by DNS resolvers are now normalised via `.Unmap()` in all resolution paths, preventing false denials in `resolves_to` comparisons.
- Empty resolved address slice no longer vacuously passes the `resolves_to` check.
- Resolution errors no longer double-wrap `ErrPermissionDenied` in the error message string.
- Exceeding the CNAME chain depth limit now returns a clear "CNAME chain exceeds maximum depth" error instead of the misleading "domain did not resolve to any IP addresses".

---

## [v1.0.5] - 2026-03-20

### Changed
- Refactored approval state locking: `sync.Mutex` moved into a dedicated `approvalState` struct for clearer ownership and easier testing.

---

## [v1.0.4] - 2026-03-19

### Fixed
- Fixed incorrect `caddy.RegisterModule()` call.
- Fixed failing unit tests.

---

## [v1.0.3] - 2026-03-18

### Changed
- Updated and tidied Go module dependencies (`go mod tidy`).

---

## [v1.0.2] - 2026-03-17

### Fixed
- Fixed module initialization.

---

## [v1.0.1] - 2026-03-17

### Fixed
- Fixed struct initialization.

---

## [v1.0.0] - 2026-03-17

### Added
- Initial release.
- Core policy engine implementing the Caddy `OnDemandPermission` interface.
- `allow_regexp` and `deny_regexp` for hostname matching via regular expressions.
- `allow_subdomain` and `deny_subdomain` for exact subdomain literal matching.
- `resolves_to` for validating that a hostname resolves to a specific target.
- `max_subdomain_depth` to limit the number of subdomain labels.
- `max_certs_per_domain` to cap unique approved names per registrable domain, with approval state persisted in Caddy storage and shared across instances.
- `permit_ip` to allow direct IP address certificate requests.
- `permit_local` to allow hostnames resolving to local/private/loopback addresses.
- `permit_all` to bypass all policy checks.
- Fail-secure design: hostnames denied by default, must satisfy all configured policies.
- Short-lived 2-minute in-memory cache for at-capacity domains to avoid repeated storage reads.
- Caddyfile and JSON configuration support.
- GitHub Actions CI workflow.
