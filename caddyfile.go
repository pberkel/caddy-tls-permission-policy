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
			case "nameserver":
				p.Nameserver = append(p.Nameserver, configVal...)
			case "max_subdomain_depth":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to max_subdomain_depth")
				}
				maxSubdomainDepth, err := strconv.Atoi(configVal[0])
				if err != nil {
					return d.Errf("invalid integer value for max_subdomain_depth: %s", configVal[0])
				}
				p.MaxSubdomainDepth = maxSubdomainDepth
			case "max_certs_per_domain":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to max_certs_per_domain")
				}
				maxCertsPerDomain, err := strconv.Atoi(configVal[0])
				if err != nil {
					return d.Errf("invalid integer value for max_certs_per_domain: %s", configVal[0])
				}
				p.MaxCertsPerDomain = maxCertsPerDomain
			case "permit_ip":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to permit_ip")
				}
				permitIP, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for permit_ip: %s", configVal[0])
				}
				p.PermitIP = permitIP
			case "permit_local":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to permit_local")
				}
				permitLocal, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for permit_local: %s", configVal[0])
				}
				p.PermitLocal = permitLocal
			case "permit_all":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to permit_all")
				}
				permitAll, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for permit_all: %s", configVal[0])
				}
				p.PermitAll = permitAll
			case "rate_limit":
				if len(configVal) != 2 {
					return d.Err("rate_limit requires exactly two arguments: limit and duration")
				}
				limit, err := strconv.Atoi(configVal[0])
				if err != nil {
					return d.Errf("invalid integer value for rate_limit limit: %s", configVal[0])
				}
				dur, err := caddy.ParseDuration(configVal[1])
				if err != nil {
					return d.Errf("invalid duration value for rate_limit: %s", configVal[1])
				}
				p.GlobalRateLimit = &RateLimit{Limit: limit, Duration: caddy.Duration(dur)}
			case "per_domain_rate_limit":
				if len(configVal) != 2 {
					return d.Err("per_domain_rate_limit requires exactly two arguments: limit and duration")
				}
				limit, err := strconv.Atoi(configVal[0])
				if err != nil {
					return d.Errf("invalid integer value for per_domain_rate_limit limit: %s", configVal[0])
				}
				dur, err := caddy.ParseDuration(configVal[1])
				if err != nil {
					return d.Errf("invalid duration value for per_domain_rate_limit: %s", configVal[1])
				}
				p.PerDomainRateLimit = &RateLimit{Limit: limit, Duration: caddy.Duration(dur)}
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
	p.replacer = caddy.NewReplacer()
	p.storage = ctx.Storage()
	p.dnsClient = nil
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
		p.MaxSubdomainDepth == -1 &&
		p.MaxCertsPerDomain == -1 &&
		p.GlobalRateLimit == nil &&
		p.PerDomainRateLimit == nil &&
		!p.PermitIP &&
		!p.PermitLocal {
		return fmt.Errorf("at least one policy setting must be configured unless 'permit_all' is true")
	}

	// Normalize input parameters and build lookup sets for O(1) subdomain matching.
	p.allowSubdomainSet = make(map[string]struct{}, len(p.AllowSubdomain))
	for i, subdomain := range p.AllowSubdomain {
		subdomain = p.replacer.ReplaceAll(subdomain, "")
		subdomain = strings.ToLower(subdomain)
		p.AllowSubdomain[i] = subdomain
		p.allowSubdomainSet[subdomain] = struct{}{}
	}
	p.denySubdomainSet = make(map[string]struct{}, len(p.DenySubdomain))
	for i, subdomain := range p.DenySubdomain {
		subdomain = p.replacer.ReplaceAll(subdomain, "")
		subdomain = strings.ToLower(subdomain)
		p.DenySubdomain[i] = subdomain
		p.denySubdomainSet[subdomain] = struct{}{}
	}

	// Compile regular expressions if provided.
	for _, r := range p.AllowRegexp {
		r = p.replacer.ReplaceAll(r, "")
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("compilation of allow regexp '%s' failed: %w", r, err)
		}
		p.allowRegexp = append(p.allowRegexp, re)
	}
	for _, r := range p.DenyRegexp {
		r = p.replacer.ReplaceAll(r, "")
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("compilation of deny regexp '%s' failed: %w", r, err)
		}
		p.denyRegexp = append(p.denyRegexp, re)
	}

	// replace ResolvesTo & Nameserver placeholder values if present
	for i, value := range p.ResolvesTo {
		p.ResolvesTo[i] = p.replacer.ReplaceAll(value, "")
	}
	for i, value := range p.Nameserver {
		value = p.replacer.ReplaceAll(value, "")
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return fmt.Errorf("invalid nameserver %q: must be in host:port form", value)
		}
		if host == "" {
			return fmt.Errorf("invalid nameserver %q: host must not be empty", value)
		}
		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNum == 0 {
			return fmt.Errorf("invalid nameserver %q: port must be a number between 1 and 65535", value)
		}
		p.Nameserver[i] = value
	}
	if len(p.Nameserver) > 0 {
		p.dnsClient = &miekgdns.Client{Timeout: customDNSTimeout}
	}

	// Validate and initialize rate limit state.
	if p.GlobalRateLimit != nil {
		if p.GlobalRateLimit.Limit <= 0 {
			return fmt.Errorf("global_rate_limit limit must be greater than 0, got %d", p.GlobalRateLimit.Limit)
		}
		if time.Duration(p.GlobalRateLimit.Duration) <= 0 {
			return fmt.Errorf("global_rate_limit duration must be greater than 0")
		}
	}
	if p.PerDomainRateLimit != nil {
		if p.PerDomainRateLimit.Limit <= 0 {
			return fmt.Errorf("per_domain_rate_limit limit must be greater than 0, got %d", p.PerDomainRateLimit.Limit)
		}
		if time.Duration(p.PerDomainRateLimit.Duration) <= 0 {
			return fmt.Errorf("per_domain_rate_limit duration must be greater than 0")
		}
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
			zap.Int("nameserver_count", len(p.Nameserver)),
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
