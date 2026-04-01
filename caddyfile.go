// Copyright 2026 Pieter Berkel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tlspermissionpolicy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	miekgdns "github.com/miekg/dns"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const customDNSTimeout = 5 * time.Second

func init() {
	caddy.RegisterModule(PermissionByPolicy{})
}

// CaddyModule returns the Caddy module information.
func (PermissionByPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.permission.policy",
		New: func() caddy.Module {
			return &PermissionByPolicy{
				MaxSubdomainDepth: defaultMaxSubdomainDepth,
				MaxCertsPerDomain: defaultMaxCertsPerDomain,
			}
		},
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *PermissionByPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	parseBoolInto := func(dest *bool, key string, vals []string) error {
		if len(vals) > 1 {
			return d.Errf("too many arguments supplied to %s", key)
		}
		v, err := strconv.ParseBool(vals[0])
		if err != nil {
			return d.Errf("invalid boolean value for %s: %s", key, vals[0])
		}
		*dest = v
		return nil
	}

	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			// Obtain configuration key and parameters on the same line.
			configKey := d.Val()
			configVal := d.RemainingArgs()

			// Configuration item with nested parameter list.
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				configVal = append(configVal, d.Val())
			}

			// No valid configurations where configVal slice is empty.
			if len(configVal) == 0 {
				return d.Errf("no value supplied for configuration key '%s'", configKey)
			}

			switch configKey {
			case "allow_regexp":
				p.AllowRegexp = append(p.AllowRegexp, configVal...)
			case "deny_regexp":
				p.DenyRegexp = append(p.DenyRegexp, configVal...)
			case "allow_subdomain":
				p.AllowSubdomain = append(p.AllowSubdomain, configVal...)
			case "deny_subdomain":
				p.DenySubdomain = append(p.DenySubdomain, configVal...)
			case "resolves_to":
				p.ResolvesTo = append(p.ResolvesTo, configVal...)
			case "resolvers":
				p.Resolvers = append(p.Resolvers, configVal...)
			case "max_subdomain_depth":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to max_subdomain_depth")
				}
				p.MaxSubdomainDepthRaw = configVal[0]
			case "max_certs_per_domain":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to max_certs_per_domain")
				}
				p.MaxCertsPerDomainRaw = configVal[0]
			case "permit_ip":
				if err := parseBoolInto(&p.PermitIP, configKey, configVal); err != nil {
					return err
				}
			case "permit_local":
				if err := parseBoolInto(&p.PermitLocal, configKey, configVal); err != nil {
					return err
				}
			case "permit_all":
				if err := parseBoolInto(&p.PermitAll, configKey, configVal); err != nil {
					return err
				}
			case "rate_limit":
				if len(configVal) != 2 {
					return d.Err("rate_limit requires exactly two arguments: limit and duration")
				}
				p.GlobalRateLimit = &RateLimit{LimitRaw: configVal[0], DurationRaw: configVal[1]}
			case "per_domain_rate_limit":
				if len(configVal) != 2 {
					return d.Err("per_domain_rate_limit requires exactly two arguments: limit and duration")
				}
				p.PerDomainRateLimit = &RateLimit{LimitRaw: configVal[0], DurationRaw: configVal[1]}
			default:
				return d.Errf("unrecognized configuration parameter: %s", configKey)
			}
		}
	}
	return nil
}

// Provision prepares derived state needed during permission checks.
func (p *PermissionByPolicy) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	replacer := caddy.NewReplacer()
	p.storage = ctx.Storage()
	p.allowRegexp = nil
	p.denyRegexp = nil
	p.lookupNetIP = net.DefaultResolver.LookupNetIP
	p.approvals = &approvalState{
		atCapacityDomains: make(map[string]time.Time),
		now:               time.Now,
	}
	p.resolvedTargets = &resolvedTargetsCache{
		now: time.Now,
	}

	// Replace placeholders in max_subdomain_depth and max_certs_per_domain raw values (set
	// during Caddyfile parsing) and parse them into the concrete fields used at runtime.
	if p.MaxSubdomainDepthRaw != "" {
		raw := replacer.ReplaceAll(p.MaxSubdomainDepthRaw, "")
		val, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid integer value for max_subdomain_depth: %s", raw)
		}
		p.MaxSubdomainDepth = val
	}
	if p.MaxCertsPerDomainRaw != "" {
		raw := replacer.ReplaceAll(p.MaxCertsPerDomainRaw, "")
		val, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid integer value for max_certs_per_domain: %s", raw)
		}
		p.MaxCertsPerDomain = val
	}

	// Validate integer settings: -1 means "no limit"; values below -1 are not valid.
	if p.MaxSubdomainDepth < -1 {
		return fmt.Errorf("max_subdomain_depth must be -1 (no limit) or >= 0, got %d", p.MaxSubdomainDepth)
	}
	if p.MaxCertsPerDomain < -1 {
		return fmt.Errorf("max_certs_per_domain must be -1 (no limit) or >= 0, got %d", p.MaxCertsPerDomain)
	}

	// Ensure at least one policy option is configured in the module.
	if !p.PermitAll &&
		len(p.AllowRegexp) == 0 &&
		len(p.DenyRegexp) == 0 &&
		len(p.AllowSubdomain) == 0 &&
		len(p.DenySubdomain) == 0 &&
		len(p.ResolvesTo) == 0 &&
		p.MaxSubdomainDepth < 0 &&
		p.MaxCertsPerDomain < 0 &&
		p.GlobalRateLimit == nil &&
		p.PerDomainRateLimit == nil &&
		!p.PermitIP &&
		!p.PermitLocal {
		return fmt.Errorf("at least one policy setting must be configured unless 'permit_all' is true")
	}

	// Normalize input parameters and build lookup sets for O(1) subdomain matching.
	p.allowSubdomainSet = make(map[string]struct{}, len(p.AllowSubdomain))
	for i, subdomain := range p.AllowSubdomain {
		subdomain = replacer.ReplaceAll(subdomain, "")
		subdomain = strings.ToLower(subdomain)
		p.AllowSubdomain[i] = subdomain
		p.allowSubdomainSet[subdomain] = struct{}{}
	}
	p.denySubdomainSet = make(map[string]struct{}, len(p.DenySubdomain))
	for i, subdomain := range p.DenySubdomain {
		subdomain = replacer.ReplaceAll(subdomain, "")
		subdomain = strings.ToLower(subdomain)
		p.DenySubdomain[i] = subdomain
		p.denySubdomainSet[subdomain] = struct{}{}
	}

	// Compile regular expressions if provided.
	for _, r := range p.AllowRegexp {
		r = replacer.ReplaceAll(r, "")
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("compilation of allow regexp '%s' failed: %w", r, err)
		}
		p.allowRegexp = append(p.allowRegexp, re)
	}
	for _, r := range p.DenyRegexp {
		r = replacer.ReplaceAll(r, "")
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("compilation of deny regexp '%s' failed: %w", r, err)
		}
		p.denyRegexp = append(p.denyRegexp, re)
	}

	// replace ResolvesTo & Resolvers placeholder values if present
	for i, value := range p.ResolvesTo {
		p.ResolvesTo[i] = replacer.ReplaceAll(value, "")
	}
	for i, value := range p.Resolvers {
		value = replacer.ReplaceAll(value, "")
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			// No port specified — treat entire value as host and default to port 53.
			host = value
			port = "53"
			value = net.JoinHostPort(host, port)
		}
		if host == "" {
			return fmt.Errorf("invalid resolver %q: host must not be empty", value)
		}
		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNum == 0 {
			return fmt.Errorf("invalid resolver %q: port must be a number between 1 and 65535", value)
		}
		p.Resolvers[i] = value
	}
	if len(p.Resolvers) > 0 {
		p.dnsClient = &miekgdns.Client{Timeout: customDNSTimeout}
	}

	// Replace placeholders in rate limit raw values (set during Caddyfile parsing) and
	// parse them into the concrete Limit and Duration fields used at runtime.
	if err := p.GlobalRateLimit.resolve(replacer, "rate_limit"); err != nil {
		return err
	}
	if err := p.PerDomainRateLimit.resolve(replacer, "per_domain_rate_limit"); err != nil {
		return err
	}

	// Validate and initialize rate limit state.
	if err := p.GlobalRateLimit.validate("global_rate_limit"); err != nil {
		return err
	}
	if err := p.PerDomainRateLimit.validate("per_domain_rate_limit"); err != nil {
		return err
	}
	p.rateLimiter = &rateLimitState{
		globalLimit:    p.GlobalRateLimit,
		perDomainLimit: p.PerDomainRateLimit,
		domains:        make(map[string]*windowCounter),
		now:            time.Now,
	}

	if c := p.logger.Check(zapcore.InfoLevel, "provisioned tls.permission.policy"); c != nil {
		c.Write(
			zap.Int("allow_regexp_count", len(p.AllowRegexp)),
			zap.Int("deny_regexp_count", len(p.DenyRegexp)),
			zap.Int("allow_subdomain_count", len(p.AllowSubdomain)),
			zap.Int("deny_subdomain_count", len(p.DenySubdomain)),
			zap.Int("resolves_to_count", len(p.ResolvesTo)),
			zap.Int("resolvers_count", len(p.Resolvers)),
			zap.Int("max_subdomain_depth", p.MaxSubdomainDepth),
			zap.Int("max_certs_per_domain", p.MaxCertsPerDomain),
			zap.Bool("permit_ip", p.PermitIP),
			zap.Bool("permit_local", p.PermitLocal),
			zap.Bool("permit_all", p.PermitAll),
			zap.Bool("global_rate_limit", p.GlobalRateLimit != nil),
			zap.Bool("per_domain_rate_limit", p.PerDomainRateLimit != nil),
		)
	}

	return nil
}

// Interface guards.
var (
	_ caddytls.OnDemandPermission = (*PermissionByPolicy)(nil)
	_ caddyfile.Unmarshaler       = (*PermissionByPolicy)(nil)
	_ caddy.Provisioner           = (*PermissionByPolicy)(nil)
)
