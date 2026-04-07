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
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func TestCertificateAllowed(t *testing.T) {
	t.Run("permit_all bypasses hostname policy checks", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.PermitAll = true

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows regex match", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("normalizes uppercase and trailing dot before regexp matching", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "API.EXAMPLE.COM."); err != nil {
			t.Fatalf("expected normalized hostname to be allowed, got %v", err)
		}
	})

	t.Run("denies empty name after normalization", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.PermitLocal = true

		err := policy.CertificateAllowed(context.Background(), ".")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("permit_all bypasses IP checks", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.PermitAll = true

		if err := policy.CertificateAllowed(context.Background(), "127.0.0.1"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("denies names matching deny_regexp", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}
		policy.denyRegexp = mustCompileRegexps(t, policy.DenyRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("denies names matching deny_subdomain", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.DenySubdomain = []string{"blocked"}
		policy.denySubdomainSet = buildSubdomainSet(policy.DenySubdomain)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("deny_subdomain takes precedence over allow_regexp", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.DenySubdomain = []string{"blocked"}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.denySubdomainSet = buildSubdomainSet(policy.DenySubdomain)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows names matching allow_subdomain", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowSubdomain = []string{"www"}
		policy.allowSubdomainSet = buildSubdomainSet(policy.AllowSubdomain)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"www.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "www.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows apex name when allow_subdomain contains empty string", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowSubdomain = []string{""}
		policy.allowSubdomainSet = buildSubdomainSet(policy.AllowSubdomain)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("denies when allow_subdomain is configured and does not match", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowSubdomain = []string{"www"}
		policy.allowSubdomainSet = buildSubdomainSet(policy.AllowSubdomain)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "api.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("deny_regexp takes precedence over allow_regexp", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.denyRegexp = mustCompileRegexps(t, policy.DenyRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("denies when regexp policy is configured and does not match", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"example.net": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "example.net")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("denies when hostname label count exceeds configured maximum", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxSubdomainDepth = 2
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"deep.api.v2.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "deep.api.v2.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows when hostname label count matches configured maximum", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxSubdomainDepth = 2
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.v2.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.v2.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows effective domain when max_subdomain_depth is zero", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxSubdomainDepth = 0
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows when only max_subdomain_depth is configured and limit is satisfied", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.MaxSubdomainDepth = 1
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows local IP when explicitly permitted", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.PermitIP = true
		policy.PermitLocal = true

		if err := policy.CertificateAllowed(context.Background(), "127.0.0.1"); err != nil {
			t.Fatalf("expected local IP to be allowed, got %v", err)
		}
	})
}

func newTestPolicy(t *testing.T) *PermissionByPolicy {
	t.Helper()

	policy := &PermissionByPolicy{
		MaxSubdomainDepth: defaultMaxSubdomainDepth,
	}
	policy.logger = zap.NewNop()
	policy.lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("no fake resolver configured for %q", host)
	}
	policy.resolvedTargets = &resolvedTargetsCache{
		now: time.Now,
	}
	return policy
}

func buildSubdomainSet(subdomains []string) map[string]struct{} {
	set := make(map[string]struct{}, len(subdomains))
	for _, s := range subdomains {
		set[s] = struct{}{}
	}
	return set
}

func mustCompileRegexps(t *testing.T, patterns []string) []*regexp.Regexp {
	t.Helper()

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("failed to compile regexp %q: %v", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled
}
