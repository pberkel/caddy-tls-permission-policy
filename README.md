# caddy-tls-permission-policy

This module implements the Caddy Server [OnDemandPermission](https://caddyserver.com/docs/automatic-https#on-demand-tls) [interface](https://pkg.go.dev/github.com/caddyserver/caddy/v2/modules/caddytls#OnDemandPermission) to control permissions for on-demand TLS certificate requests. It is useful in cases where specific hostnames requiring TLS certificates are not known and cannot be directly configured (such as a SaaS provider that allows customer-supplied domains) but can be defined through explicit policy rules. The module also implements several control mechanisms designed to prevent abuse.

### Build Instructions

The module can be built using xcaddy:

```sh
xcaddy build --with github.com/pberkel/caddy-tls-permission-policy
```

## Configuration

### Caddyfile

Configure the module in an on-demand TLS permission block, the below example demonstrates all possible policy options:

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

Options `allow_regexp`, `deny_regexp`, `allow_subdomain`, `deny_subdomain`, and `resolves_to` accept multiple input values either on the same line (delimited by space characters) or in a nested block.

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

- `allow_regexp`
  A list of one or more regular expressions. Hostnames that match at least one regular expression will be allowed.
  Patterns are matched against the normalized (lowercased, trailing-dot-stripped) hostname.
- `deny_regexp`
  A list of one or more regular expressions. Hostnames that match any regular expression will be denied.
  Patterns are matched against the normalized (lowercased, trailing-dot-stripped) hostname.
- `allow_subdomain`
  Allow hostnames whose subdomain portion exactly matches one of these string literals.
  Use `""` to match the domain apex, for example `example.com`.
  Values are normalized to lowercase during module provisioning.
- `deny_subdomain`
  Deny hostnames whose subdomain portion exactly matches one of these string literals.
  Use `""` to match the domain apex, for example `example.com`.
  Values are normalized to lowercase during module provisioning.
- `resolves_to`
  A list of one or more hostnames or IP addresses, typically mapping to the Caddy server that will be performing the TLS certificate request.
  All IPs that the requested name resolves to must be present in the set of IPs produced by the configured targets — if even one resolved IP is absent, the request is denied.
  Resolved target IP addresses are cached in memory for 5 minutes to avoid repeated DNS lookups on every certificate request.
- `resolvers`
  A list of one or more name servers used to resolve DNS queries, each must be in the format HOST:PORT. If not specified, the system resolver will be used.
- `max_subdomain_depth`
  Maximum number of subdomain labels measured to the left of the domain. Default: -1 (no limit).
  `example.com` counts as `0`, `www.example.com` counts as `1`, `api.v2.example.com` counts as `2`.
  A typical policy allowing the apex domain `example.com` and one subdomain level `(www|api|app).example.com` would set `max_subdomain_depth` to 1.
  Accepts a Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) value (e.g. `{env.MAX_SUBDOMAIN_DEPTH}`), resolved at provisioning time.
  When set via Caddyfile the value is stored as `max_subdomain_depth_raw` in the JSON representation; when set directly via JSON use the integer `max_subdomain_depth` field instead.
  NOTE: many ACME certificate providers set an internal limit of 10 subdomain labels.
- `max_certs_per_domain`
  Maximum number of unique approved names per domain. Default: -1 (no limit).
  Approval state is persisted in Caddy storage, so the limit survives restarts and is shared by multiple Caddy instances using the same storage backend.
  Accepts a Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) value (e.g. `{env.MAX_CERTS_PER_DOMAIN}`), resolved at provisioning time.
  When set via Caddyfile the value is stored as `max_certs_per_domain_raw` in the JSON representation; when set directly via JSON use the integer `max_certs_per_domain` field instead.
- `rate_limit`
  Limit the total number of certificate approvals across all domains within a rolling time window.
  Requires two arguments: `limit` (maximum number of approvals) and `duration` (the window length, e.g. `1h`, `30m`).
  Only approved requests count against the limit. The check is applied early to avoid unnecessary DNS resolution for over-limit requests.
  Both arguments accept Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) values (e.g. `{env.RATE_LIMIT}`), resolved at provisioning time.
  When set via Caddyfile the values are stored as `limit_raw` and `duration_raw` in the JSON representation; when set directly via JSON use the integer `limit` and duration string `duration` fields instead.
- `per_domain_rate_limit`
  Limit the number of certificate approvals per registrable domain (e.g. `example.com`) within a rolling time window.
  Requires two arguments: `limit` and `duration`. Each registrable domain has its own independent counter.
  Only approved requests count against the limit. Counters are held in memory only and reset when Caddy restarts.
  Both arguments accept Caddy [placeholder](https://caddyserver.com/docs/conventions#placeholders) values (e.g. `{env.DOMAIN_RATE_LIMIT}`), resolved at provisioning time.
  When set via Caddyfile the values are stored as `limit_raw` and `duration_raw` in the JSON representation; when set directly via JSON use the integer `limit` and duration string `duration` fields instead.
- `permit_ip`
  Allow a certificate to be issued when the name is a direct IP address (only useful for Caddy internal / self-signed certificates). Default: false.
  When enabled, IP address names bypass all other policy checks (`deny_regexp`, `allow_regexp`, subdomain rules, `max_certs_per_domain`, rate limits) and are evaluated only against `permit_local` and `resolves_to`.
- `permit_local`
  Allow a certificate to be issued to names that resolve to local, private, loopback, link-local, or unspecified addresses. Default: false.
  Note: when `permit_local` is false (the default), DNS resolution is performed on every certificate request — even for policies that use only `allow_regexp`, `deny_regexp`, `allow_subdomain`, or `deny_subdomain` — in order to verify that the hostname does not resolve to a local address. Set `permit_local true` to skip this check and avoid the resolution overhead if local addresses are not a concern in your deployment.
- `permit_all`
  Bypass all policy checks and allow every certificate request. Should never be used in production. Default: false.

## Important Behavior Notes

- This module is fail-secure: if a hostname does not satisfy the configured policy, it is denied. Conversely, a hostname must match all configured policies to be accepted.
- The module requires at least one policy option to be configured unless `permit_all` is true. Accepted options are `allow_regexp`, `deny_regexp`, `allow_subdomain`, `deny_subdomain`, `resolves_to`, `max_subdomain_depth`, `max_certs_per_domain`, `rate_limit`, `per_domain_rate_limit`, `permit_ip`, and `permit_local`.
- `permit_all` bypasses all policy checks for both hostnames and direct IP names.
- Subdomain policies compare against the portion to the left of the domain, for example:
  `example.com` -> `""`, `www.example.com` -> `"www"`, `api.v2.example.com` -> `"api.v2"`.
- `max_subdomain_depth` and subdomain literal checks (`deny_subdomain`, `allow_subdomain`) run before regexp checks (`deny_regexp`, `allow_regexp`).
- `max_certs_per_domain` is stored in Caddy storage. Counts survive restarts and are shared across Caddy instances using the same storage backend.
- `max_certs_per_domain` applies to DNS hostnames, not direct IP names.
- Hostname approval uses exact per-name deduplication per domain in storage, so repeated requests for the same approved name do not consume the limit again.
- The module keeps a short-lived 2-minute in-memory cache of domains that have reached `max_certs_per_domain` so that requests for already-full domains are rejected quickly without a storage read.
- If `resolves_to` is configured, the requested name must resolve successfully and all of its resolved IPs must be present in the target set before it can be approved.
- `rate_limit` and `per_domain_rate_limit` counters are in-memory only and are not shared across Caddy instances. Counts reset when Caddy restarts.
- `per_domain_rate_limit` maintains one counter per approved registrable domain for the lifetime of the process. In deployments serving a very large number of unique domains, pairing it with `rate_limit` is recommended to bound the total number of tracked domains.

## Policy Order

For each requested certificate name, the module applies a policy with the following checks:

- Direct IP names are denied unless `permit_ip` is enabled.
- Direct IP names and resolved hostnames are denied if they use local, private, loopback, link-local, or unspecified IPs unless `permit_local` is enabled.
- If `rate_limit` is configured, the global approval count is checked and hostnames over the limit are denied before DNS resolution.
- If `max_certs_per_domain` is configured and the domain is cached as already full, the limit is rechecked immediately (fast rejection before more expensive checks).
- If `per_domain_rate_limit` is configured, the per-domain approval count is checked and hostnames over the limit are denied before regexp and DNS checks.
- Hostnames with label count exceeding `max_subdomain_depth` are denied.
- Hostnames whose subdomain portion matches any configured `deny_subdomain` literal are denied.
- If `allow_subdomain` is configured, the subdomain portion must match at least one configured `allow_subdomain` literal.
- Hostnames matching any configured `deny_regexp` pattern are denied.
- If `allow_regexp` is configured, hostnames must match at least one configured `allow_regexp` pattern.
- If `resolves_to` is configured, all resolved IPs for the requested hostname must be present in the set of IPs produced by the configured `resolves_to` targets.
- If `max_certs_per_domain` is configured, the limit is authoritatively checked and the approval recorded in Caddy storage.
- If `rate_limit` or `per_domain_rate_limit` is configured, the approval is recorded in the respective in-memory counter.
