package tlspermissionpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestCertificateAllowedDNS(t *testing.T) {
	t.Run("wraps hostname lookup failures as permission denied", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)

		err := policy.CertificateAllowed(context.Background(), "missing.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})

	t.Run("allows configured resolves_to target", func(t *testing.T) {
		policy := newTestPolicy(t)
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
		policy := newTestPolicy(t)
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

	t.Run("denies regex match when any resolved address is outside resolves_to targets", func(t *testing.T) {
		policy := newTestPolicy(t)
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
		policy := newTestPolicy(t)
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
		policy := newTestPolicy(t)
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
}

func fakeResolver(records map[string][]netip.Addr) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if addrs, ok := records[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("host not found")
	}
}
