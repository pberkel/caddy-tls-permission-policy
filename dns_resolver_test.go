package tlspermissionpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
	miekgdns "github.com/miekg/dns"
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

	t.Run("uses configured nameserver for hostname resolution", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"api.example.com.": {netip.MustParseAddr("203.0.113.44")},
		}, nil)

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.PermitLocal = true
		policy.Nameserver = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow using nameserver-backed resolution, got %v", err)
		}
	})

	t.Run("follows CNAME records with configured nameserver", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"target.example.com.": {netip.MustParseAddr("203.0.113.55")},
		}, map[string]string{
			"alias.example.com.": "target.example.com.",
		})

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^alias\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.PermitLocal = true
		policy.Nameserver = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{})

		if err := policy.CertificateAllowed(context.Background(), "alias.example.com"); err != nil {
			t.Fatalf("expected allow using nameserver-backed CNAME resolution, got %v", err)
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

func startTestDNSServer(t *testing.T, records map[string][]netip.Addr, cnames map[string]string) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	server := &miekgdns.Server{
		PacketConn: pc,
		Handler: miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
			msg := new(miekgdns.Msg)
			msg.SetReply(r)

			for _, question := range r.Question {
				if target, ok := cnames[question.Name]; ok {
					msg.Answer = append(msg.Answer, &miekgdns.CNAME{
						Hdr:    miekgdns.RR_Header{Name: question.Name, Rrtype: miekgdns.TypeCNAME, Class: miekgdns.ClassINET, Ttl: 60},
						Target: target,
					})
				}
				for _, addr := range records[question.Name] {
					switch {
					case question.Qtype == miekgdns.TypeA && addr.Is4():
						msg.Answer = append(msg.Answer, &miekgdns.A{
							Hdr: miekgdns.RR_Header{Name: question.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60},
							A:   addr.AsSlice(),
						})
					case question.Qtype == miekgdns.TypeAAAA && addr.Is6():
						msg.Answer = append(msg.Answer, &miekgdns.AAAA{
							Hdr:  miekgdns.RR_Header{Name: question.Name, Rrtype: miekgdns.TypeAAAA, Class: miekgdns.ClassINET, Ttl: 60},
							AAAA: addr.AsSlice(),
						})
					}
				}
			}

			if err := w.WriteMsg(msg); err != nil {
				t.Errorf("write dns response: %v", err)
			}
		}),
	}

	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = pc.Close()
	})

	return pc.LocalAddr().String()
}
