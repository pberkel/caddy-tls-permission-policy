# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- `max_certs_per_domain` configuration option and all associated approval state persistence. Certificate cap functionality is out of scope for this module.
- `rate_limit` and `per_domain_rate_limit` configuration options and all associated in-memory sliding-window counters. Issuance rate limiting is now provided by [`caddy-issuer-rate-limit`](https://github.com/pberkel/caddy-issuer-rate-limit), which enforces limits after `SubjectTransformer` has run (on effective certificate subjects rather than raw hostnames).

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
