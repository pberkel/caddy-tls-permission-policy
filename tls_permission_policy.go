package tlspermissionpolicy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

func init() {
	caddy.RegisterModule(PermissionByPolicy{})
}

type PermissionByPolicy struct {
	// Allow certificates for hostnames matching at least one regular expression pattern.
	AllowRegexp []string `json:"allow_regexp,omitempty"`
	// Deny certificates for hostnames matching any regular expression pattern.
	DenyRegexp []string `json:"deny_regexp,omitempty"`
	// Allow certificates for hostnames whose effective subdomain matches one of these string literals.
	AllowSubdomain []string `json:"allow_subdomain,omitempty"`
	// Deny certificates for hostnames whose effective subdomain matches one of these string literals.
	DenySubdomain []string `json:"deny_subdomain,omitempty"`
	// Allow certificates for hostnames that resolve to a specified hostname or IP address.
	ResolvesTo []string `json:"resolves_to,omitempty"`
	// The maximum number of unique names approved per registrable domain. Default 0 means no limit.
	MaxCertsPerDomain int `json:"max_certs_per_domain"`
	// The maximum hostname label count measured from the effective domain upward. A bare effective domain counts as 1. Default 0 means no limit.
	MaxDomainLabels int `json:"max_domain_labels"`
	// Allow certificates for IP address hosts. Default: false.
	PermitIp bool `json:"permit_ip"`
	// Allow certificates for hostnames resolving to local, loopback, private, or unspecified addresses. Default: false.
	PermitLocal bool `json:"permit_local"`
	// Allow all names without applying hostname policy checks. Default: false.
	PermitAll bool `json:"permit_all"`

	logger      *zap.Logger                                                 `json:"-"`
	replacer    *caddy.Replacer                                             `json:"-"`
	allowRegexp []*regexp.Regexp                                            `json:"-"`
	denyRegexp  []*regexp.Regexp                                            `json:"-"`
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error) `json:"-"`
	approvals   *approvalState                                              `json:"-"`
}

type approvalState struct {
	mu            sync.Mutex
	approvedNames map[string]map[string]struct{}
}

// CaddyModule returns the Caddy module information.
func (PermissionByPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.permission.policy",
		New: func() caddy.Module {
			return new(PermissionByPolicy)
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
			case "max_domain_labels":
				if len(configVal) > 1 {
					return d.Err("too many arguments supplied to max_domain_labels")
				}
				maxDomainLabels, err := strconv.Atoi(configVal[0])
				if err != nil {
					return d.Errf("invalid integer value for max_domain_labels: %s", configVal[0])
				}
				p.MaxDomainLabels = maxDomainLabels
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
				permitIp, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for permit_ip: %s", configVal[0])
				}
				p.PermitIp = permitIp
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
	p.allowRegexp = nil
	p.denyRegexp = nil
	p.lookupNetIP = net.DefaultResolver.LookupNetIP
	p.approvals = &approvalState{
		approvedNames: make(map[string]map[string]struct{}),
	}
	// Normalize input parameters
	for i, subdomain := range p.AllowSubdomain {
		p.AllowSubdomain[i] = strings.ToLower(subdomain)
	}
	for i, subdomain := range p.DenySubdomain {
		p.DenySubdomain[i] = strings.ToLower(subdomain)
	}

	// Ensure at least one policy option is configured in the module.
	if !p.PermitAll &&
		len(p.AllowRegexp) == 0 &&
		len(p.DenyRegexp) == 0 &&
		len(p.AllowSubdomain) == 0 &&
		len(p.DenySubdomain) == 0 &&
		len(p.ResolvesTo) == 0 &&
		p.MaxDomainLabels == 0 &&
		p.MaxCertsPerDomain == 0 &&
		!p.PermitIp &&
		!p.PermitLocal {
		return fmt.Errorf("at least one policy setting must be configured unless 'permit_all' is true")
	}

	// Compile regular expressions if provided.
	for _, r := range p.AllowRegexp {
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("compilation of allow regexp '%s' failed: %w", r, err)
		}
		p.allowRegexp = append(p.allowRegexp, re)
	}
	for _, r := range p.DenyRegexp {
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("compilation of deny regexp '%s' failed: %w", r, err)
		}
		p.denyRegexp = append(p.denyRegexp, re)
	}

	if c := p.logger.Check(zapcore.InfoLevel, "provisioned tls.permission.policy"); c != nil {
		c.Write(
			zap.Int("allow_regexp_count", len(p.AllowRegexp)),
			zap.Int("deny_regexp_count", len(p.DenyRegexp)),
			zap.Int("allow_subdomain_count", len(p.AllowSubdomain)),
			zap.Int("deny_subdomain_count", len(p.DenySubdomain)),
			zap.Int("resolves_to_count", len(p.ResolvesTo)),
			zap.Int("max_domain_labels", p.MaxDomainLabels),
			zap.Int("max_certs_per_domain", p.MaxCertsPerDomain),
			zap.Bool("permit_ip", p.PermitIp),
			zap.Bool("permit_local", p.PermitLocal),
			zap.Bool("permit_all", p.PermitAll),
		)
	}

	return nil
}

// CertificateAllowed evaluates the configured policy for a requested certificate name.
func (p *PermissionByPolicy) CertificateAllowed(ctx context.Context, name string) error {
	// This policy should never be enabled in production.
	if p.PermitAll {
		if c := p.logger.Check(zapcore.DebugLevel, "permit_all bypassed policy checks"); c != nil {
			c.Write(zap.String("name", name))
		}
		return nil
	}

	// Check if name is actually an IP address.
	if addr, err := netip.ParseAddr(name); err == nil {
		if c := p.logger.Check(zapcore.DebugLevel, "evaluating IP name policy"); c != nil {
			c.Write(zap.String("name", name), zap.String("ip", addr.String()))
		}
		if !p.PermitIp {
			return fmt.Errorf("%w: name is an IP address", caddytls.ErrPermissionDenied)
		}
		if !p.PermitLocal && isLocalIP(addr) {
			return fmt.Errorf("%w: IP address is local", caddytls.ErrPermissionDenied)
		}
		if len(p.ResolvesTo) > 0 {
			if err := p.checkResolvesTo(ctx, []netip.Addr{addr}); err != nil {
				return err
			}
		}
		// Name is an IP address and specifically allowed by configured policy.
		// Certificates issuance will only succeed if Caddy is configured to
		// Generate self-signed certificates using the `tls internal` option.
		return nil
	}

	// Normalize name by remove trailing dot and lowercasing.
	originalName := name
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return fmt.Errorf("%w: empty name is not allowed", caddytls.ErrPermissionDenied)
	}
	if c := p.logger.Check(zapcore.DebugLevel, "evaluating hostname policy"); c != nil {
		c.Write(zap.String("name", originalName), zap.String("normalized_name", name))
	}

	// Resolve name into IP adddress(es) for policy checks.
	var resolvedName []netip.Addr
	if !p.PermitLocal || len(p.ResolvesTo) > 0 {
		resolved, err := p.resolveAddrs(ctx, name)
		if err != nil {
			return fmt.Errorf("%w: resolving name %q: %v", caddytls.ErrPermissionDenied, name, err)
		}
		resolvedName = resolved

		if !p.PermitLocal {
			for _, addr := range resolvedName {
				if isLocalIP(addr) {
					return fmt.Errorf("%w: name resolves to local IP %s", caddytls.ErrPermissionDenied, addr)
				}
			}
		}
		// ResolvesTo policy enforcement requires expensive DNS lookups,
		// So the code to check is after less-expensive policy enforcement.
	}

	// Determine the effective domain (from the public suffix list)
	// And subdomain (everything to the left of the effective domain).
	effectiveSubdomain, effectiveDomain := "", name
	if len(p.DenySubdomain) > 0 || len(p.AllowSubdomain) > 0 || p.MaxDomainLabels > 0 || p.MaxCertsPerDomain > 0 {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			return fmt.Errorf("%w: determining effective domain for %q: %w", caddytls.ErrPermissionDenied, name, err)
		}
		effectiveDomain = domain
		if effectiveDomain != name {
			effectiveSubdomain = strings.TrimSuffix(name, "."+effectiveDomain)
		}

		// Deny names whose effective subdomain matches any configured deny_subdomain literal.
		if len(p.DenySubdomain) > 0 {
			deniedSubdomain := false
			for _, subdomain := range p.DenySubdomain {
				if effectiveSubdomain == subdomain {
					deniedSubdomain = true
					break
				}
			}
			if c := p.logger.Check(zapcore.DebugLevel, "evaluated deny_subdomain policy"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Int("subdomain_count", len(p.DenySubdomain)),
					zap.Bool("matched", deniedSubdomain),
				)
			}
			if deniedSubdomain {
				return fmt.Errorf("%w: effective subdomain matched deny_subdomain", caddytls.ErrPermissionDenied)
			}
		}

		// Allow names whose effective subdomain matches at least one configured allow_subdomain literal.
		if len(p.AllowSubdomain) > 0 {
			allowedSubdomain := false
			for _, subdomain := range p.AllowSubdomain {
				if effectiveSubdomain == subdomain {
					allowedSubdomain = true
					break
				}
			}
			if c := p.logger.Check(zapcore.DebugLevel, "evaluated allow_subdomain policy"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Int("subdomain_count", len(p.AllowSubdomain)),
					zap.Bool("matched", allowedSubdomain),
				)
			}
			if !allowedSubdomain {
				return fmt.Errorf("%w: effective subdomain did not match any allow_subdomain", caddytls.ErrPermissionDenied)
			}
		}

		// Check the number of domain labels does not exceed configured limit.
		if p.MaxDomainLabels > 0 {
			var labels int
			if effectiveSubdomain == "" {
				labels = 1
			} else {
				labels = len(strings.Split(effectiveSubdomain, ".")) + 1
			}
			if c := p.logger.Check(zapcore.DebugLevel, "evaluated max_domain_labels policy"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_domain", effectiveDomain),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Int("labels", labels),
					zap.Int("max_domain_labels", p.MaxDomainLabels),
				)
			}
			if labels > p.MaxDomainLabels {
				return fmt.Errorf("%w: name label depth %d exceeds configured maximum %d", caddytls.ErrPermissionDenied, labels, p.MaxDomainLabels)
			}
		}

		// Perform an early limit check so requests that are already over the cap can fail
		// Before more expensive regexp and DNS-based policy evaluation. The limit is
		// Checked again in checkCertsPerDomain() immediately before recording approval.
		if p.MaxCertsPerDomain > 0 {
			p.approvals.mu.Lock()
			domainApprovals := p.approvals.approvedNames[effectiveDomain]
			_, alreadyApproved := domainApprovals[effectiveSubdomain]
			approvalCount := len(domainApprovals)
			p.approvals.mu.Unlock()
			if c := p.logger.Check(zapcore.DebugLevel, "evaluated max_certs_per_domain pre-check"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_domain", effectiveDomain),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Bool("already_approved", alreadyApproved),
					zap.Int("approval_count", approvalCount),
					zap.Int("max_certs_per_domain", p.MaxCertsPerDomain),
				)
			}

			if !alreadyApproved && approvalCount >= p.MaxCertsPerDomain {
				return fmt.Errorf("%w: certificate approval limit reached for %s", caddytls.ErrPermissionDenied, effectiveDomain)
			}
		}
	}

	// Deny names that match any configured deny_regexp pattern.
	if len(p.denyRegexp) > 0 {
		matchedRegexp := false
		for _, re := range p.denyRegexp {
			if re.MatchString(name) {
				matchedRegexp = true
				break
			}
		}
		if c := p.logger.Check(zapcore.DebugLevel, "evaluated deny_regexp policy"); c != nil {
			c.Write(
				zap.String("name", name),
				zap.Int("regexp_count", len(p.denyRegexp)),
				zap.Bool("matched", matchedRegexp),
			)
		}
		if matchedRegexp {
			return fmt.Errorf("%w: name matched deny regexp", caddytls.ErrPermissionDenied)
		}
	}

	// Allow names that match at least one configured allow_regexp pattern.
	if len(p.allowRegexp) > 0 {
		matchedRegexp := false
		for _, re := range p.allowRegexp {
			if re.MatchString(name) {
				matchedRegexp = true
				break
			}
		}
		if c := p.logger.Check(zapcore.DebugLevel, "evaluated allow_regexp policy"); c != nil {
			c.Write(
				zap.String("name", name),
				zap.Int("regexp_count", len(p.allowRegexp)),
				zap.Bool("matched", matchedRegexp),
			)
		}
		// Fail if no supplied regexp matched name.
		if !matchedRegexp {
			return fmt.Errorf("%w: name did not match any allow regexp", caddytls.ErrPermissionDenied)
		}
	}

	// Check whether name resolves to one of the provided hostnames / IPs (which
	// Should point to this server) to ensure ACME HTTP-01 challenge is successful.
	if len(p.ResolvesTo) > 0 {
		if err := p.checkResolvesTo(ctx, resolvedName); err != nil {
			return err
		}
	}

	// Re-check the per-domain limit immediately before recording approval so the
	// Authoritative decision is made in the same locked section as the mutation.
	if p.MaxCertsPerDomain > 0 {
		if err := p.checkCertsPerDomain(effectiveDomain, effectiveSubdomain); err != nil {
			return err
		}
	}

	if c := p.logger.Check(zapcore.DebugLevel, "certificate request allowed by policy"); c != nil {
		c.Write(
			zap.String("name", name),
			zap.String("effective_domain", effectiveDomain),
			zap.String("effective_subdomain", effectiveSubdomain),
		)
	}

	return nil
}

// Resolve a hostname or literal IP into one or more IP addresses.
func (p *PermissionByPolicy) resolveAddrs(ctx context.Context, name string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(name); err == nil {
		if c := p.logger.Check(zapcore.DebugLevel, "resolved literal IP address"); c != nil {
			c.Write(zap.String("name", name), zap.String("ip", addr.String()))
		}
		return []netip.Addr{addr}, nil
	}

	resolved, err := p.lookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", name, err)
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("%w: domain did not resolve to any IP addresses", caddytls.ErrPermissionDenied)
	}
	if c := p.logger.Check(zapcore.DebugLevel, "resolved hostname addresses"); c != nil {
		c.Write(zap.String("name", name), zap.Any("resolved_addrs", resolved))
	}

	return resolved, nil
}

// Ensure the resolved name addresses match one of the configured targets.
func (p *PermissionByPolicy) checkResolvesTo(ctx context.Context, resolved []netip.Addr) error {
	// AllowedTargets is a map of IP addresses extracted from "resolve_to" parameters.
	allowedTargets := make(map[netip.Addr]struct{})
	for _, target := range p.ResolvesTo {
		targetAddrs, err := p.resolveAddrs(ctx, target)
		if err != nil {
			return fmt.Errorf("%w: resolving resolves_to target %q: %v", caddytls.ErrPermissionDenied, target, err)
		}
		for _, addr := range targetAddrs {
			allowedTargets[addr] = struct{}{}
		}
	}
	if c := p.logger.Check(zapcore.DebugLevel, "evaluated resolves_to targets"); c != nil {
		c.Write(
			zap.Any("resolved_addrs", resolved),
			zap.Any("allowed_targets", allowedTargets),
		)
	}

	for _, addr := range resolved {
		if _, ok := allowedTargets[addr]; !ok {
			return fmt.Errorf("%w: domain resolved to disallowed target %s", caddytls.ErrPermissionDenied, addr)
		}
	}

	return nil
}

// CheckCertsPerDomain tracks unique approved names for in-process per-domain limits.
func (p *PermissionByPolicy) checkCertsPerDomain(effectiveDomain, effectiveSubdomain string) error {

	p.approvals.mu.Lock()
	defer p.approvals.mu.Unlock()

	// Check if effective domain has been previously stored.
	domainApprovals, ok := p.approvals.approvedNames[effectiveDomain]
	if !ok {
		domainApprovals = make(map[string]struct{})
		p.approvals.approvedNames[effectiveDomain] = domainApprovals
	}

	// Check if name has previously been approved.
	if _, ok := domainApprovals[effectiveSubdomain]; ok {
		if c := p.logger.Check(zapcore.DebugLevel, "effective subdomain already approved"); c != nil {
			c.Write(
				zap.String("effective_domain", effectiveDomain),
				zap.String("effective_subdomain", effectiveSubdomain),
			)
		}
		return nil
	}

	// Check if specified subdomain limit has been reached.
	if c := p.logger.Check(zapcore.DebugLevel, "evaluating effective domain certificate limit"); c != nil {
		c.Write(
			zap.String("effective_domain", effectiveDomain),
			zap.String("effective_subdomain", effectiveSubdomain),
			zap.Int("approval_count", len(domainApprovals)),
			zap.Int("max_certs_per_domain", p.MaxCertsPerDomain),
		)
	}
	if len(domainApprovals) >= p.MaxCertsPerDomain {
		return fmt.Errorf("%w: certificate approval limit reached for %s", caddytls.ErrPermissionDenied, effectiveDomain)
	}

	domainApprovals[effectiveSubdomain] = struct{}{}
	return nil
}

// Determine whether an address is loopback, private, link-local, or unspecified.
func isLocalIP(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}

// Interface guards
var (
	_ caddytls.OnDemandPermission = (*PermissionByPolicy)(nil)
	_ caddyfile.Unmarshaler       = (*PermissionByPolicy)(nil)
	_ caddy.Provisioner           = (*PermissionByPolicy)(nil)
)
