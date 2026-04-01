# caddy-tls-permission-policy

This module implements the Caddy Server [OnDemandPermission](https://caddyserver.com/docs/automatic-https#on-demand-tls) [interface](https://pkg.go.dev/github.com/caddyserver/caddy/v2/modules/caddytls#OnDemandPermission) to control permissions for on-demand TLS certificate requests. It is useful in cases where specific hostnames requiring TLS certificates are not known and cannot be directly configured (such as a SaaS provider that allows customer-supplied domains) but can be defined through explicit policy rules. The module also implements several control mechanisms designed to prevent abuse.

## Build Instructions

The module can be built using xcaddy:

```sh
xcaddy build --with github.com/pberkel/caddy-tls-permission-policy
```

## Configuration

### Caddyfile

Configure the module in an on-demand TLS permission block. The example below demonstrates all possible policy options:

```caddyfile
{
	on_demand_tls {
		permission policy {
			allow_regexp ^([a-z0-9-]+)\.example\.com$
			deny_regexp ^(blocked|secret)\.example\.com$
			allow_subdomain www api ""
			deny_subdomain internal private
			resolvers 8.8.8.8:53
			resolves_to my-caddy-server.example.net
			max_subdomain_depth 1
			max_certs_per_domain 20
			rate_limit 100 1h
			per_domain_rate_limit 5 24h
			permit_ip false
			permit_local false
			permit_all false
		}
	}
}

https:// {
	tls {
		on_demand
	}
}
```

Options `allow_regexp`, `deny_regexp`, `allow_subdomain`, `deny_subdomain`, and `resolves_to` accept multiple input values either on the same line (delimited by spaces) or in a nested block.

### JSON

The same configuration can be represented in JSON. This is a config snippet rather than a complete Caddy config:

```json
		"tls": {
			"automation": {
				"policies": [
					{
						"on_demand": true
					}
				],
				"on_demand": {
					"permission": {
						"allow_regexp": [
							"^([a-z0-9-]+)\\.example\\.com$"
						],
						"allow_subdomain": [
							"www",
							"api",
							""
						],
						"deny_regexp": [
							"^(blocked|secret)\\.example\\.com$"
						],
						"deny_subdomain": [
							"internal",
							"private"
						],
						"max_certs_per_domain": 20,
						"max_subdomain_depth": 1,
						"module": "policy",
						"permit_all": false,
						"permit_ip": false,
						"permit_local": false,
						"resolvers": [
							"8.8.8.8:53"
						],
						"resolves_to": [
							"my-caddy-server.example.net"
						],
						"global_rate_limit": {
							"limit": 100,
							"duration": "1h"
						},
						"per_domain_rate_limit": {
							"limit": 5,
							"duration": "24h"
						}
					}
				}
			}
		}
```

### Policy Options

| Option | Arguments | Default | Description |
|--------|-----------|---------|-------------|
| `allow_regexp` | `pattern...` | — | Allow hostnames matching at least one regular expression. Patterns are matched against the normalized (lowercased, trailing-dot-stripped) hostname. |
| `deny_regexp` | `pattern...` | — | Deny hostnames matching any regular expression. Patterns are matched against the normalized hostname. |
| `allow_subdomain` | `label...` | — | Allow hostnames whose subdomain portion exactly matches one of these literals. Use `""` to match the domain apex (e.g. `example.com`). Values are normalized to lowercase at provisioning time. |
| `deny_subdomain` | `label...` | — | Deny hostnames whose subdomain portion exactly matches one of these literals. Use `""` to match the domain apex. Values are normalized to lowercase at provisioning time. |
| `resolves_to` | `target...` | — | Allow only hostnames whose resolved IPs are all present in the set produced by these targets (hostnames or IPs). Resolved target IPs are cached in memory for 5 minutes. |
| `resolvers` | `HOST:PORT...` | system | Custom DNS resolvers used for hostname resolution instead of the system resolver. |
| `max_subdomain_depth` | `integer` | `-1` (no limit) | Maximum subdomain label depth to the left of the registrable domain. `example.com` = 0, `www.example.com` = 1, `api.v2.example.com` = 2. Note: many ACME providers enforce an internal limit of 10 labels. Supports Caddy [placeholders](https://caddyserver.com/docs/conventions#placeholders). |
| `max_certs_per_domain` | `integer` | `-1` (no limit) | Maximum number of unique approved hostnames per registrable domain. Approval state is persisted in Caddy storage and shared across instances using the same backend. Supports Caddy [placeholders](https://caddyserver.com/docs/conventions#placeholders). |
| `rate_limit` | `limit duration` | — | Global rolling-window cap on certificate approvals across all domains (e.g. `100 1h`). Only approved requests count. Checked early to avoid unnecessary DNS resolution. Supports Caddy [placeholders](https://caddyserver.com/docs/conventions#placeholders). |
| `per_domain_rate_limit` | `limit duration` | — | Per-registrable-domain rolling-window cap (e.g. `5 24h`). Each domain has its own independent in-memory counter, reset on restart. Supports Caddy [placeholders](https://caddyserver.com/docs/conventions#placeholders). |
| `permit_ip` | `bool` | `false` | Allow certificates for direct IP address names. When enabled, IP names bypass regexp, subdomain, `max_certs_per_domain`, and rate limit checks, and are evaluated only against `permit_local` and `resolves_to`. |
| `permit_local` | `bool` | `false` | Allow names resolving to local, private, loopback, link-local, or unspecified addresses. When false (the default), DNS resolution is performed on every request to verify the hostname does not resolve locally — even for regexp/subdomain-only policies. |
| `permit_all` | `bool` | `false` | Bypass all policy checks and allow every certificate request. Should never be used in production. |

> **Caddyfile vs JSON for numeric/duration fields:** When `max_subdomain_depth`, `max_certs_per_domain`, `rate_limit`, or `per_domain_rate_limit` are set via Caddyfile, their raw string values (which may contain placeholders) are stored in the corresponding `_raw` JSON fields (`max_subdomain_depth_raw`, `max_certs_per_domain_raw`, `limit_raw`, `duration_raw`) and resolved at provisioning time. When configuring directly via JSON, use the concrete integer/duration fields instead.

## Important Behavior Notes

- This module is fail-secure: a hostname must satisfy **all** configured policies to be approved; any failure results in denial.
- At least one policy option must be configured unless `permit_all` is `true`. Valid options are `allow_regexp`, `deny_regexp`, `allow_subdomain`, `deny_subdomain`, `resolves_to`, `max_subdomain_depth`, `max_certs_per_domain`, `rate_limit`, `per_domain_rate_limit`, `permit_ip`, and `permit_local`.
- `permit_all` bypasses all policy checks for both hostnames and direct IP names.
- Subdomain policies compare against the portion to the left of the registrable domain: `example.com` → `""`, `www.example.com` → `"www"`, `api.v2.example.com` → `"api.v2"`.
- `max_subdomain_depth` and subdomain literal checks (`allow_subdomain`, `deny_subdomain`) run before regexp checks (`allow_regexp`, `deny_regexp`).
- `max_certs_per_domain` applies to DNS hostnames only, not direct IP names.
- `max_certs_per_domain` uses exact per-name deduplication in Caddy storage, so repeated requests for the same approved hostname do not consume the limit again.
- A short-lived 2-minute in-memory cache tracks domains that have reached `max_certs_per_domain`, allowing fast rejection without a storage read.
- If `resolves_to` is configured, the requested name must resolve successfully and all of its resolved IPs must be present in the target set.
- `rate_limit` and `per_domain_rate_limit` counters are in-memory only and are not shared across Caddy instances. Counts reset on restart.
- In deployments serving a very large number of unique domains, pairing `per_domain_rate_limit` with `rate_limit` is recommended to bound the total number of tracked per-domain counters.

## Policy Order

For each requested certificate name, the module applies checks in this order:

1. Deny direct IP names unless `permit_ip` is enabled.
2. Deny direct IP names and resolved hostnames that use local, private, loopback, link-local, or unspecified IPs unless `permit_local` is enabled.
3. If `rate_limit` is configured, check the global approval count and deny hostnames over the limit (before DNS resolution).
4. If `max_certs_per_domain` is configured and the domain is cached as full, recheck the limit immediately (fast rejection before more expensive checks).
5. If `per_domain_rate_limit` is configured, check the per-domain approval count and deny hostnames over the limit (before regexp and DNS checks).
6. Deny hostnames whose subdomain label count exceeds `max_subdomain_depth`.
7. Deny hostnames whose subdomain portion matches any configured `deny_subdomain` literal.
8. If `allow_subdomain` is configured, deny hostnames whose subdomain portion does not match at least one configured literal.
9. Deny hostnames matching any configured `deny_regexp` pattern.
10. If `allow_regexp` is configured, deny hostnames that do not match at least one configured pattern.
11. If `resolves_to` is configured, deny hostnames whose resolved IPs are not all present in the set produced by the configured targets.
12. If `max_certs_per_domain` is configured, authoritatively check the limit and record the approval in Caddy storage.
13. If `rate_limit` or `per_domain_rate_limit` is configured, record the approval in the respective in-memory counter.
