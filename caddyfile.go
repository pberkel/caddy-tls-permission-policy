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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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
				return d.Errf("no value supplied for configuraton key '%s'", configKey)
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
				p.PermitIp = permitIP
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
	p.allowRegexp = nil
	p.denyRegexp = nil
	p.lookupNetIP = net.DefaultResolver.LookupNetIP
	p.approvals = &approvalState{
		atCapacityDomains: make(map[string]time.Time),
		now:               time.Now,
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
		!p.PermitIp &&
		!p.PermitLocal {
		return fmt.Errorf("at least one policy setting must be configured unless 'permit_all' is true")
	}

	// Normalize input parameters.
	for i, subdomain := range p.AllowSubdomain {
		subdomain = p.replacer.ReplaceAll(subdomain, "")
		p.AllowSubdomain[i] = strings.ToLower(subdomain)
	}
	for i, subdomain := range p.DenySubdomain {
		subdomain = p.replacer.ReplaceAll(subdomain, "")
		p.DenySubdomain[i] = strings.ToLower(subdomain)
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
		p.Nameserver[i] = p.replacer.ReplaceAll(value, "")
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
			zap.Bool("permit_ip", p.PermitIp),
			zap.Bool("permit_local", p.PermitLocal),
			zap.Bool("permit_all", p.PermitAll),
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
