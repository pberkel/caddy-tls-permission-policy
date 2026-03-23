package tlspermissionpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

const defaultMaxSubdomainDepth = -1
const defaultMaxCertsPerDomain = -1
const approvalLimitCacheTTL = 2 * time.Minute

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
	// The maximum number of unique names approved per registrable domain. Default -1 no limit.
	MaxCertsPerDomain int `json:"max_certs_per_domain"`
	// The maximum subdomain depth measured to the left of the effective domain. The effective domain itself has depth 0. Default -1 no limit.
	MaxSubdomainDepth int `json:"max_subdomain_depth,omitempty"`
	// Allow certificates for IP address hosts. Default: false.
	PermitIp bool `json:"permit_ip"`
	// Allow certificates for hostnames resolving to local, loopback, private, or unspecified addresses. Default: false.
	PermitLocal bool `json:"permit_local"`
	// Allow all names without applying hostname policy checks. Default: false.
	PermitAll bool `json:"permit_all"`

	logger      *zap.Logger                                                 `json:"-"`
	replacer    *caddy.Replacer                                             `json:"-"`
	storage     certmagic.Storage                                           `json:"-"`
	allowRegexp []*regexp.Regexp                                            `json:"-"`
	denyRegexp  []*regexp.Regexp                                            `json:"-"`
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error) `json:"-"`
	approvals   *approvalState                                              `json:"-"`
}

type approvalState struct {
	mu                sync.Mutex
	atCapacityDomains map[string]time.Time
	now               func() time.Time
}

type storedDomainApprovals struct {
	Subdomains []string `json:"subdomains"`
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
	if c := p.logger.Check(zapcore.DebugLevel, "evaluating hostname policy"); c != nil {
		c.Write(zap.String("name", originalName), zap.String("normalized_name", name))
	}
	if name == "" {
		return fmt.Errorf("%w: empty name is not allowed", caddytls.ErrPermissionDenied)
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
		// So the code to check will execute after less-expensive policy enforcement.
	}

	// Determine the effective domain (from the public suffix list)
	// And subdomain (everything to the left of the effective domain).
	effectiveSubdomain, effectiveDomain := "", name
	certsPerDomainChecked := false
	if p.MaxCertsPerDomain >= 0 || p.MaxSubdomainDepth >= 0 || len(p.DenySubdomain) > 0 || len(p.AllowSubdomain) > 0 {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			return fmt.Errorf("%w: determining effective domain for %q: %w", caddytls.ErrPermissionDenied, name, err)
		}
		effectiveDomain = domain
		if effectiveDomain != name {
			effectiveSubdomain = strings.TrimSuffix(name, "."+effectiveDomain)
		}

		// Perform an early limit check so requests that are already over the cap can fail
		// Before more expensive regexp and DNS-based policy evaluation. The limit is
		// Checked again in checkCertsPerDomain() immediately before recording approval.
		if p.MaxCertsPerDomain >= 0 {
			cachedFull := p.checkCachedCertsPerDomainLimit(effectiveDomain)
			if c := p.logger.Check(zapcore.DebugLevel, "evaluated max_certs_per_domain pre-check"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_domain", effectiveDomain),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Bool("cache_hit", cachedFull),
				)
			}

			if cachedFull {
				certsPerDomainChecked = true
				if err := p.checkCertsPerDomain(ctx, effectiveDomain, effectiveSubdomain); err != nil {
					return err
				}
			}
		}

		// Check the number of domain labels does not exceed configured limit.
		if p.MaxSubdomainDepth >= 0 {
			var labels int
			if effectiveSubdomain == "" {
				labels = 0
			} else {
				labels = len(strings.Split(effectiveSubdomain, "."))
			}
			if c := p.logger.Check(zapcore.DebugLevel, "evaluated max_subdomain_depth policy"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_domain", effectiveDomain),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Int("labels", labels),
					zap.Int("max_subdomain_depth", p.MaxSubdomainDepth),
				)
			}
			if labels > p.MaxSubdomainDepth {
				return fmt.Errorf("%w: name label depth %d exceeds configured maximum %d", caddytls.ErrPermissionDenied, labels, p.MaxSubdomainDepth)
			}
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
		// Fail if any supplied regexp matched name.
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

	// Check whether name resolves to one of the provided hostnames / IPs (which should point
	// to this server) to ensure ACME HTTP-01 or TLS-ALPN-01 challenge will be successful.
	if len(p.ResolvesTo) > 0 {
		if err := p.checkResolvesTo(ctx, resolvedName); err != nil {
			return err
		}
	}

	// Re-check the per-domain limit immediately before recording approval so the
	// Authoritative decision is made in the same locked section as the mutation.
	if p.MaxCertsPerDomain >= 0 && !certsPerDomainChecked {
		if err := p.checkCertsPerDomain(ctx, effectiveDomain, effectiveSubdomain); err != nil {
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

// CheckCertsPerDomain tracks unique approved names in shared storage for per-domain limits.
func (p *PermissionByPolicy) checkCertsPerDomain(ctx context.Context, effectiveDomain, effectiveSubdomain string) error {
	lockKey := approvalResourceKey(effectiveDomain)
	if err := p.storage.Lock(ctx, lockKey); err != nil {
		return fmt.Errorf("locking approval state for %s: %w", effectiveDomain, err)
	}
	unlockCtx := context.WithoutCancel(ctx)
	defer func() {
		if err := p.storage.Unlock(unlockCtx, lockKey); err != nil && p.logger != nil {
			p.logger.Error(
				"unlocking approval state",
				zap.String("effective_domain", effectiveDomain),
				zap.Error(err),
			)
		}
	}()

	domainApprovals, err := p.loadDomainApprovals(ctx, effectiveDomain)
	if err != nil {
		return err
	}

	if _, ok := domainApprovals[effectiveSubdomain]; ok {
		if c := p.logger.Check(zapcore.DebugLevel, "effective subdomain already approved"); c != nil {
			c.Write(
				zap.String("effective_domain", effectiveDomain),
				zap.String("effective_subdomain", effectiveSubdomain),
			)
		}
		if len(domainApprovals) >= p.MaxCertsPerDomain {
			p.cacheAtCapacityDomain(effectiveDomain)
		}
		return nil
	}

	if c := p.logger.Check(zapcore.DebugLevel, "evaluating effective domain certificate limit"); c != nil {
		c.Write(
			zap.String("effective_domain", effectiveDomain),
			zap.String("effective_subdomain", effectiveSubdomain),
			zap.Int("approval_count", len(domainApprovals)),
			zap.Int("max_certs_per_domain", p.MaxCertsPerDomain),
		)
	}

	if len(domainApprovals) >= p.MaxCertsPerDomain {
		p.cacheAtCapacityDomain(effectiveDomain)
		return fmt.Errorf("%w: certificate approval limit reached for %s", caddytls.ErrPermissionDenied, effectiveDomain)
	}

	domainApprovals[effectiveSubdomain] = struct{}{}
	if err := p.storeDomainApprovals(ctx, effectiveDomain, domainApprovals); err != nil {
		return err
	}
	if len(domainApprovals) >= p.MaxCertsPerDomain {
		p.cacheAtCapacityDomain(effectiveDomain)
	}

	return nil
}

// CheckCachedCertsPerDomainLimit returns whether a domain is temporarily cached as full.
func (p *PermissionByPolicy) checkCachedCertsPerDomainLimit(effectiveDomain string) bool {
	now := p.approvals.now()

	p.approvals.mu.Lock()
	defer p.approvals.mu.Unlock()

	expiresAt, ok := p.approvals.atCapacityDomains[effectiveDomain]
	if !ok {
		return false
	}
	if now.After(expiresAt) {
		delete(p.approvals.atCapacityDomains, effectiveDomain)
		return false
	}
	return true
}

// LoadDomainApprovals reads the persisted approval set for a registrable domain.
func (p *PermissionByPolicy) loadDomainApprovals(ctx context.Context, effectiveDomain string) (map[string]struct{}, error) {
	approvalBytes, err := p.storage.Load(ctx, approvalResourceKey(effectiveDomain))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return make(map[string]struct{}), nil
		}
		return nil, fmt.Errorf("loading approval state for %s: %w", effectiveDomain, err)
	}

	var stored storedDomainApprovals
	if err := json.Unmarshal(approvalBytes, &stored); err != nil {
		return nil, fmt.Errorf("decoding approval state for %s: %w", effectiveDomain, err)
	}

	domainApprovals := make(map[string]struct{}, len(stored.Subdomains))
	for _, subdomain := range stored.Subdomains {
		domainApprovals[subdomain] = struct{}{}
	}
	return domainApprovals, nil
}

// StoreDomainApprovals persists the approval set for a registrable domain.
func (p *PermissionByPolicy) storeDomainApprovals(ctx context.Context, effectiveDomain string, domainApprovals map[string]struct{}) error {
	subdomains := make([]string, 0, len(domainApprovals))
	for subdomain := range domainApprovals {
		subdomains = append(subdomains, subdomain)
	}
	sort.Strings(subdomains)

	approvalBytes, err := json.Marshal(storedDomainApprovals{Subdomains: subdomains})
	if err != nil {
		return fmt.Errorf("encoding approval state for %s: %w", effectiveDomain, err)
	}
	if err := p.storage.Store(ctx, approvalResourceKey(effectiveDomain), approvalBytes); err != nil {
		return fmt.Errorf("storing approval state for %s: %w", effectiveDomain, err)
	}

	return nil
}

// CacheAtCapacityDomain keeps a short-lived local marker for domains that reached the certificate limit.
func (p *PermissionByPolicy) cacheAtCapacityDomain(effectiveDomain string) {
	p.approvals.mu.Lock()
	defer p.approvals.mu.Unlock()
	p.approvals.atCapacityDomains[effectiveDomain] = p.approvals.now().Add(approvalLimitCacheTTL)
}

// ApprovalResourceKey returns the storage key for persisted approvals.
func approvalResourceKey(effectiveDomain string) string {
	return path.Join("tls_permission_policy", "approvals", effectiveDomain+".json")
}

// Determine whether an address is loopback, private, link-local, or unspecified.
func isLocalIP(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}
