# caddy-tls-permission-policy

This module implements the Caddy Server [OnDemandPermission](https://caddyserver.com/docs/automatic-https#on-demand-tls) [interface](https://pkg.go.dev/github.com/caddyserver/caddy/v2/modules/caddytls#OnDemandPermission) to control permissions for on-demand TLS certificate requests. It is useful in cases where specific hostnames requiring TLS certificates are not known and cannot be directly configured (such as a SaaS provider that allows customer-supplied domains) but can be defined through explicit policy rules. The module also implements several control mechanisms designed to prevent abuse.

> **Rate limiting:** Certificate issuance rate limiting is not provided by this module. Use [`caddy-tls-issuer-rate-limit`](https://github.com/pberkel/caddy-tls-issuer-rate-limit) for configurable per-domain and global issuance rate limits.

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
			max_subdomain_depth 1
			resolvers 8.8.8.8
			resolves_to my-caddy-server.example.net
			dns_timeout 5s
			permit_ip false
			permit_local false
			permit_all false
			debug false
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
						"max_subdomain_depth": 1,
						"module": "policy",
						"permit_all": false,
						"permit_ip": false,
						"permit_local": false,
						"resolvers": [
							"8.8.8.8"
						],
						"resolves_to": [
							"my-caddy-server.example.net"
						],
						"dns_timeout": 5000000000
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
| `resolves_to` | `target...` | — | Allow only hostnames whose DNS resolution chain shares at least one element — an intermediate CNAME name or final IP address — with the chains produced by resolving these targets (hostnames or literal IPs). When `resolvers` is configured, intermediate CNAME names are collected and matched; without `resolvers` the system resolver is used and only IP addresses are compared. Resolved target chains are cached in memory for 5 minutes. |
| `resolvers` | `HOST\|HOST:PORT...` | system | Custom DNS resolvers used for hostname resolution instead of the system resolver. Port defaults to `53` when omitted. |
| `dns_timeout` | `duration` | `5s` | Timeout for each DNS query when `resolvers` is configured. Accepts a Go duration string (e.g. `10s`, `500ms`). Increase this when using a recursive resolver (e.g. Unbound) where cold lookups may involve multiple upstream queries. Supports Caddy [placeholders](https://caddyserver.com/docs/conventions#placeholders). |
| `max_subdomain_depth` | `integer` | `-1` (no limit) | Maximum subdomain label depth to the left of the registrable domain. `example.com` = 0, `www.example.com` = 1, `api.v2.example.com` = 2. Note: many ACME providers enforce an internal limit of 10 labels. Supports Caddy [placeholders](https://caddyserver.com/docs/conventions#placeholders). |
| `permit_ip` | `bool` | `false` | Allow certificates for direct IP address names. When enabled, IP names bypass regexp and subdomain checks, and are evaluated only against `permit_local` and `resolves_to`. Since Let's Encrypt began issuing certificates for public IP addresses (January 2026), enabling this option can result in real publicly-trusted certificates being obtained. Pairing `permit_ip` with `resolves_to` is strongly recommended to restrict issuance to IP addresses known to belong to this server. |
| `permit_local` | `bool` | `false` | Allow names resolving to local, private, loopback, link-local, or unspecified addresses. When false (the default), DNS resolution is performed on every request to verify the hostname does not resolve locally — even for regexp/subdomain-only policies. |
| `permit_all` | `bool` | `false` | Bypass all policy checks and allow every certificate request. Should never be used in production. |
| `debug` | `bool` | `false` | Emit per-request policy evaluation details at info level regardless of the global Caddy log level. When false, the same details are only emitted when Caddy's global log level is set to debug. |

> **Caddyfile vs JSON for duration/numeric fields:** `dns_timeout` and `max_subdomain_depth` support Caddy placeholders when set via Caddyfile. The raw string values are Caddyfile-only intermediaries and are not included in JSON output. When configuring directly via JSON, use the concrete fields instead: `dns_timeout` as nanoseconds (e.g. `5000000000` for 5s) and `max_subdomain_depth` as an integer.

## Important Behavior Notes

- This module is fail-secure: a hostname must satisfy **all** configured policies to be approved; any failure results in denial.
- At least one policy option must be configured unless `permit_all` is `true`. Valid options are `allow_regexp`, `deny_regexp`, `allow_subdomain`, `deny_subdomain`, `resolves_to`, `max_subdomain_depth`, `permit_ip`, and `permit_local`.
- `permit_all` bypasses all policy checks for both hostnames and direct IP names.
- Subdomain policies compare against the portion to the left of the registrable domain: `example.com` → `""`, `www.example.com` → `"www"`, `api.v2.example.com` → `"api.v2"`.
- `max_subdomain_depth` and subdomain literal checks (`allow_subdomain`, `deny_subdomain`) run before regexp checks (`allow_regexp`, `deny_regexp`).
- If `resolves_to` is configured, the requested name must share at least one DNS resolution chain element (CNAME name or IP address) with the set produced by resolving the configured targets.

## Policy Order

For each requested certificate name, the module applies checks in this order:

1. Deny direct IP names unless `permit_ip` is enabled.
2. Deny direct IP names and resolved hostnames that use local, private, loopback, link-local, or unspecified IPs unless `permit_local` is enabled.
3. Deny hostnames whose subdomain label count exceeds `max_subdomain_depth`.
4. Deny hostnames whose subdomain portion matches any configured `deny_subdomain` literal.
5. If `allow_subdomain` is configured, deny hostnames whose subdomain portion does not match at least one configured literal.
6. Deny hostnames matching any configured `deny_regexp` pattern.
7. If `allow_regexp` is configured, deny hostnames that do not match at least one configured pattern.
8. If `resolves_to` is configured, deny hostnames whose DNS resolution chain shares no element (CNAME name or IP address) with the set produced by resolving the configured targets.
