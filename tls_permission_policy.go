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
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
	miekgdns "github.com/miekg/dns"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
)

const defaultMaxSubdomainDepth = -1

// PermissionByPolicy determines permission for a TLS certificate by
// validating the name against a specified policy configuration.
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
	// One or more optional name server addresses used to resolve DNS queries, each in HOST:PORT format.
	Resolvers []string `json:"resolvers,omitempty"`
	// The maximum subdomain depth measured to the left of the effective domain. The effective domain itself has depth 0. Default -1 no limit.
	MaxSubdomainDepth int `json:"max_subdomain_depth"`
	// Raw string value for max_subdomain_depth; may contain Caddy placeholders resolved at provisioning time.
	// When non-empty, takes precedence over MaxSubdomainDepth. Caddyfile-only; excluded from JSON serialization.
	MaxSubdomainDepthRaw string `json:"-"`
	// Allow certificates for IP address hosts. When true, IP address names bypass all other
	// policy checks (regexp patterns, subdomain rules) and are evaluated only against the
	// permit_local and resolves_to policies. Default: false.
	PermitIP bool `json:"permit_ip"`
	// Allow certificates for hostnames resolving to local, loopback, private, or unspecified addresses. Default: false.
	PermitLocal bool `json:"permit_local"`
	// Allow all names without applying hostname policy checks. Default: false.
	PermitAll bool `json:"permit_all"`
	// When true, per-request policy evaluation details are logged at info level
	// regardless of the global Caddy log level. When false (the default), the
	// same details are only emitted when Caddy's global log level is set to debug.
	Debug bool `json:"debug,omitempty"`
	// Timeout for DNS queries when resolvers are configured. Defaults to 5s.
	DNSTimeout time.Duration `json:"dns_timeout,omitempty"`
	// Raw string value for dns_timeout; may contain Caddy placeholders resolved at provisioning time.
	// When non-empty, takes precedence over DNSTimeout. Caddyfile-only; excluded from JSON serialization.
	DNSTimeoutRaw string `json:"-"`

	logger            *zap.Logger                                                 `json:"-"`
	dnsClient         *miekgdns.Client                                            `json:"-"`
	allowRegexp       []*regexp.Regexp                                            `json:"-"`
	denyRegexp        []*regexp.Regexp                                            `json:"-"`
	allowSubdomainSet map[string]struct{}                                         `json:"-"`
	denySubdomainSet  map[string]struct{}                                         `json:"-"`
	lookupNetIP       func(context.Context, string, string) ([]netip.Addr, error) `json:"-"`
	resolvedTargets   *resolvedTargetsCache                                       `json:"-"`
}

// debugCheck returns a zap.CheckedEntry for a debug-level message. When the
// Debug flag is enabled the entry is checked at info level so it is always
// emitted regardless of the global Caddy log level. When Debug is false the
// entry is only emitted when Caddy's global log level includes debug.
func (p *PermissionByPolicy) debugCheck(msg string) *zapcore.CheckedEntry {
	if p.Debug {
		return p.logger.Check(zapcore.InfoLevel, msg)
	}
	return p.logger.Check(zapcore.DebugLevel, msg)
}

// CertificateAllowed evaluates the configured policy for a requested certificate name.
func (p *PermissionByPolicy) CertificateAllowed(ctx context.Context, name string) error {
	// This policy should never be enabled in production.
	if p.PermitAll {
		if c := p.debugCheck("permit_all bypassed policy checks"); c != nil {
			c.Write(zap.String("name", name))
		}
		return nil
	}

	// Check if name is actually an IP address.
	if addr, err := netip.ParseAddr(name); err == nil {
		if !p.PermitIP {
			return fmt.Errorf("%w: name is an IP address", caddytls.ErrPermissionDenied)
		}
		if !p.PermitLocal && isLocalIP(addr) {
			return fmt.Errorf("%w: IP address is local", caddytls.ErrPermissionDenied)
		}
		if len(p.ResolvesTo) > 0 {
			allowed, err := p.allowedTargetMembers(ctx)
			if err != nil {
				return err
			}
			if err := p.checkResolvesTo(&resolvedChain{addrs: []netip.Addr{addr}}, allowed); err != nil {
				return err
			}
		}
		// Name is an IP address and specifically allowed by configured policy.
		// Certificates issuance will only succeed if Caddy is configured to
		// generate self-signed certificates using the `tls internal` option.
		return nil
	}

	// Normalize name by remove trailing dot and lowercasing.
	originalName := name
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if c := p.debugCheck("evaluating hostname policy"); c != nil {
		c.Write(zap.String("name", originalName), zap.String("normalized_name", name))
	}
	if name == "" {
		return fmt.Errorf("%w: empty name is not allowed", caddytls.ErrPermissionDenied)
	}

	// Resolve name into IP address(es) for policy checks.
	// DNS resolution is required in two cases: when permit_local is false (to
	// reject names that resolve to local IPs) and when resolves_to is configured
	// (to validate the name resolves to the expected targets).
	var resolvedName *resolvedChain
	var earlyExit map[string]struct{}
	if !p.PermitLocal || len(p.ResolvesTo) > 0 {
		// Pre-fetch the allowed target members so that resolution of the incoming
		// hostname can terminate early as soon as a visited CNAME name matches.
		// When a CNAME name match triggers early exit, chain.addrs will be empty
		// and the permit_local IP check below is skipped — this is intentional,
		// since the hostname is already matched against an explicitly trusted target.
		if len(p.ResolvesTo) > 0 {
			var err error
			earlyExit, err = p.allowedTargetMembers(ctx)
			if err != nil {
				return err
			}
		}

		var err error
		resolvedName, err = p.resolveAddrs(ctx, name, earlyExit)
		if err != nil {
			if c := p.debugCheck("hostname resolution failed"); c != nil {
				c.Write(zap.String("name", name), zap.Error(err))
			}
			return fmt.Errorf("%w: resolving name %q: %w", caddytls.ErrPermissionDenied, name, err)
		}

		if !p.PermitLocal {
			for _, addr := range resolvedName.addrs {
				if isLocalIP(addr) {
					return fmt.Errorf("%w: name resolves to local IP %s", caddytls.ErrPermissionDenied, addr)
				}
			}
		}
		// ResolvesTo is checked last: all cheaper policy checks (subdomain, regexp) run first.
	}

	// Determine the effective domain (from the public suffix list)
	// And subdomain (everything to the left of the effective domain).
	effectiveSubdomain, effectiveDomain := "", name
	if p.MaxSubdomainDepth >= 0 || len(p.denySubdomainSet) > 0 || len(p.allowSubdomainSet) > 0 {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			return fmt.Errorf("%w: determining effective domain for %q: %w", caddytls.ErrPermissionDenied, name, err)
		}
		effectiveDomain = domain
		if effectiveDomain != name {
			effectiveSubdomain = strings.TrimSuffix(name, "."+effectiveDomain)
		}

		// Check the number of domain labels does not exceed configured limit.
		if p.MaxSubdomainDepth >= 0 {
			var labels int
			if effectiveSubdomain != "" {
				labels = strings.Count(effectiveSubdomain, ".") + 1
			}
			if c := p.debugCheck("evaluated max_subdomain_depth policy"); c != nil {
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
		if len(p.denySubdomainSet) > 0 {
			_, deniedSubdomain := p.denySubdomainSet[effectiveSubdomain]
			if c := p.debugCheck("evaluated deny_subdomain policy"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Int("subdomain_count", len(p.denySubdomainSet)),
					zap.Bool("matched", deniedSubdomain),
				)
			}
			if deniedSubdomain {
				return fmt.Errorf("%w: effective subdomain matched deny_subdomain", caddytls.ErrPermissionDenied)
			}
		}

		// Allow names whose effective subdomain matches at least one configured allow_subdomain literal.
		if len(p.allowSubdomainSet) > 0 {
			_, allowedSubdomain := p.allowSubdomainSet[effectiveSubdomain]
			if c := p.debugCheck("evaluated allow_subdomain policy"); c != nil {
				c.Write(
					zap.String("name", name),
					zap.String("effective_subdomain", effectiveSubdomain),
					zap.Int("subdomain_count", len(p.allowSubdomainSet)),
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
		if c := p.debugCheck("evaluated deny_regexp policy"); c != nil {
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
		if c := p.debugCheck("evaluated allow_regexp policy"); c != nil {
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
		if err := p.checkResolvesTo(resolvedName, earlyExit); err != nil {
			if c := p.debugCheck("resolves_to check failed"); c != nil {
				c.Write(zap.String("name", name), zap.Error(err))
			}
			return err
		}
	}

	if c := p.debugCheck("certificate request allowed by policy"); c != nil {
		c.Write(zap.String("name", name))
	}

	return nil
}

// isLocalIP determines whether an address is loopback, private, link-local, multicast, or unspecified.
func isLocalIP(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
}
