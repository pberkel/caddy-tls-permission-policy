package tlspermissionpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func TestCertificateAllowed(t *testing.T) {
	t.Run("permit_all bypasses hostname policy checks", func(t *testing.T) {
		policy := newTestPolicy()
		policy.PermitAll = true

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows regex match", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("wraps hostname lookup failures as permission denied", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)

		err := policy.CertificateAllowed(context.Background(), "missing.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("normalizes uppercase and trailing dot before regexp matching", func(t *testing.T) {
		policy := newTestPolicy()
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
		policy := newTestPolicy()
		policy.PermitLocal = true

		err := policy.CertificateAllowed(context.Background(), ".")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("permit_all bypasses IP checks", func(t *testing.T) {
		policy := newTestPolicy()
		policy.PermitAll = true

		if err := policy.CertificateAllowed(context.Background(), "127.0.0.1"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("denies names matching deny_regexp", func(t *testing.T) {
		policy := newTestPolicy()
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
		policy := newTestPolicy()
		policy.DenySubdomain = []string{"blocked"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("deny_subdomain takes precedence over allow_regexp", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.DenySubdomain = []string{"blocked"}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows names matching allow_subdomain", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowSubdomain = []string{"www"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"www.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "www.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows apex name when allow_subdomain contains empty string", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowSubdomain = []string{""}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("denies when allow_subdomain is configured and does not match", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowSubdomain = []string{"www"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "api.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("deny_regexp takes precedence over allow_regexp", func(t *testing.T) {
		policy := newTestPolicy()
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
		policy := newTestPolicy()
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
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxDomainLabels = 2
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"deep.api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "deep.api.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows when hostname label count matches configured maximum", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxDomainLabels = 2
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows effective domain when max_domain_labels is one", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxDomainLabels = 1
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows configured resolves_to target", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"target.internal"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"svc.example.com": {netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")},
			"target.internal": {netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")},
		})

		if err := policy.CertificateAllowed(context.Background(), "svc.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("wraps resolves_to target lookup failures as permission denied", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"missing.target"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"svc.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "svc.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows when only max_certs_per_domain is configured", func(t *testing.T) {
		policy := newTestPolicy()
		policy.MaxCertsPerDomain = 2
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
			"www.example.com": {netip.MustParseAddr("203.0.113.11")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected first name to be allowed, got %v", err)
		}
		if err := policy.CertificateAllowed(context.Background(), "www.example.com"); err != nil {
			t.Fatalf("expected second name in same domain to be allowed, got %v", err)
		}
	})

	t.Run("denies regex match when any resolved address is outside resolves_to targets", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"target.internal"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"svc.example.com": {netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.30")},
			"target.internal": {netip.MustParseAddr("203.0.113.20")},
		})

		err := policy.CertificateAllowed(context.Background(), "svc.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("denies domain resolving to local IP when permit_local is false", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"svc.example.com": {netip.MustParseAddr("127.0.0.1")},
		})

		err := policy.CertificateAllowed(context.Background(), "svc.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows domain resolving to local IP when permit_local is true", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.PermitLocal = true
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"svc.example.com": {netip.MustParseAddr("127.0.0.1")},
		})

		if err := policy.CertificateAllowed(context.Background(), "svc.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("caps approvals per eTLD+1 bucket", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxCertsPerDomain = 1
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
			"www.example.com": {netip.MustParseAddr("203.0.113.11")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected first name to be allowed, got %v", err)
		}
		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected repeated approval for same name to be allowed, got %v", err)
		}

		err := policy.CertificateAllowed(context.Background(), "www.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected second unique name to be denied, got %v", err)
		}
	})

	t.Run("dedupes repeated approvals for the effective domain itself", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxCertsPerDomain = 1
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected first approval to be allowed, got %v", err)
		}
		if err := policy.CertificateAllowed(context.Background(), "example.com"); err != nil {
			t.Fatalf("expected repeated approval to be allowed, got %v", err)
		}
	})

	t.Run("dedupes normalized names for max_certs_per_domain", func(t *testing.T) {
		policy := newTestPolicy()
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.MaxCertsPerDomain = 1
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected first approval to be allowed, got %v", err)
		}
		if err := policy.CertificateAllowed(context.Background(), "API.EXAMPLE.COM."); err != nil {
			t.Fatalf("expected normalized duplicate approval to be allowed, got %v", err)
		}
	})

	t.Run("allows when only max_domain_labels is configured and limit is satisfied", func(t *testing.T) {
		policy := newTestPolicy()
		policy.MaxDomainLabels = 2
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"api.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("allows local IP when explicitly permitted", func(t *testing.T) {
		policy := newTestPolicy()
		policy.PermitIp = true
		policy.PermitLocal = true

		if err := policy.CertificateAllowed(context.Background(), "127.0.0.1"); err != nil {
			t.Fatalf("expected local IP to be allowed, got %v", err)
		}
	})
}

func TestProvision(t *testing.T) {
	t.Run("fails when no policy knob is configured", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		err := policy.Provision(ctx)
		if err == nil {
			t.Fatal("expected provision error, got nil")
		}
	})

	t.Run("allows empty policy when permit_all is true", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.PermitAll = true
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only permit_ip enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.PermitIp = true
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only permit_local enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.PermitLocal = true
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only allow_regexp enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only deny_regexp enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only allow_subdomain enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.AllowSubdomain = []string{"www"}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only deny_subdomain enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.DenySubdomain = []string{"blocked"}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("normalizes allow_subdomain values to lowercase in provision", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.AllowSubdomain = []string{"WWW"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"www.example.com": {netip.MustParseAddr("203.0.113.10")},
		})
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"www.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		if err := policy.CertificateAllowed(context.Background(), "www.example.com"); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("normalizes deny_subdomain values to lowercase in provision", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.DenySubdomain = []string{"BLOCKED"}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{
			"blocked.example.com": {netip.MustParseAddr("203.0.113.10")},
		})

		err := policy.CertificateAllowed(context.Background(), "blocked.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("reprovision resets derived runtime state", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}
		policy.MaxCertsPerDomain = 1
		policy.approvedNames = make(map[string]map[string]struct{})
		policy.approvedNames["example.com"] = map[string]struct{}{"api": {}}

		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected first provision success, got %v", err)
		}
		if len(policy.allowRegexp) != 1 {
			t.Fatalf("expected 1 compiled allow regexp after first provision, got %d", len(policy.allowRegexp))
		}
		if len(policy.denyRegexp) != 1 {
			t.Fatalf("expected 1 compiled deny regexp after first provision, got %d", len(policy.denyRegexp))
		}
		if len(policy.approvedNames) != 0 {
			t.Fatalf("expected approval cache reset after first provision, got %d entries", len(policy.approvedNames))
		}

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected second provision success, got %v", err)
		}
		if len(policy.allowRegexp) != 1 {
			t.Fatalf("expected 1 compiled allow regexp after reprovision, got %d", len(policy.allowRegexp))
		}
		if len(policy.denyRegexp) != 1 {
			t.Fatalf("expected 1 compiled deny regexp after reprovision, got %d", len(policy.denyRegexp))
		}
		if len(policy.approvedNames) != 0 {
			t.Fatalf("expected approval cache reset after reprovision, got %d entries", len(policy.approvedNames))
		}
	})
}

func TestUnmarshalCaddyfileAccumulatesRepeatedDirectives(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		allow_regexp ^api\.example\.com$
		allow_regexp ^www\.example\.com$
		deny_regexp ^blocked\.example\.com$
		deny_regexp ^forbidden\.example\.com$
		allow_subdomain www
		allow_subdomain ""
		deny_subdomain blocked
		deny_subdomain private
			resolves_to 203.0.113.10
			resolves_to 203.0.113.11
			permit_all false
		}
		`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(policy.AllowRegexp) != 2 {
		t.Fatalf("expected 2 allow_regexp entries, got %d", len(policy.AllowRegexp))
	}
	if len(policy.DenyRegexp) != 2 {
		t.Fatalf("expected 2 deny_regexp entries, got %d", len(policy.DenyRegexp))
	}
	if len(policy.AllowSubdomain) != 2 {
		t.Fatalf("expected 2 allow_subdomain entries, got %d", len(policy.AllowSubdomain))
	}
	if len(policy.DenySubdomain) != 2 {
		t.Fatalf("expected 2 deny_subdomain entries, got %d", len(policy.DenySubdomain))
	}
	if len(policy.ResolvesTo) != 2 {
		t.Fatalf("expected 2 resolves_to entries, got %d", len(policy.ResolvesTo))
	}
	if policy.PermitAll {
		t.Fatal("expected permit_all to be false")
	}
}

func TestUnmarshalCaddyfileAllowsEmptyAllowSubdomainLiteral(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		allow_subdomain ""
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(policy.AllowSubdomain) != 1 {
		t.Fatalf("expected 1 allow_subdomain entry, got %d", len(policy.AllowSubdomain))
	}
	if policy.AllowSubdomain[0] != "" {
		t.Fatalf("expected empty allow_subdomain literal, got %q", policy.AllowSubdomain[0])
	}
}

func newTestPolicy() *PermissionByPolicy {
	policy := &PermissionByPolicy{}
	policy.logger = zap.NewNop()
	policy.lookupNetIP = net.DefaultResolver.LookupNetIP
	policy.approvedNames = make(map[string]map[string]struct{})
	return policy
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

func fakeResolver(records map[string][]netip.Addr) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if addrs, ok := records[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("host not found")
	}
}
