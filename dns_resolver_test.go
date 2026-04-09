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

	t.Run("denies when no resolved address matches resolves_to targets", func(t *testing.T) {
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

	t.Run("uses configured resolver for hostname resolution", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"api.example.com.": {netip.MustParseAddr("203.0.113.44")},
		}, nil)

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.PermitLocal = true
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{})

		if err := policy.CertificateAllowed(context.Background(), "api.example.com"); err != nil {
			t.Fatalf("expected allow using resolver-backed resolution, got %v", err)
		}
	})

	t.Run("follows CNAME records with configured resolver", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"target.example.com.": {netip.MustParseAddr("203.0.113.55")},
		}, map[string]string{
			"alias.example.com.": "target.example.com.",
		})

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^alias\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.PermitLocal = true
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}
		policy.lookupNetIP = fakeResolver(map[string][]netip.Addr{})

		if err := policy.CertificateAllowed(context.Background(), "alias.example.com"); err != nil {
			t.Fatalf("expected allow using resolver-backed CNAME resolution, got %v", err)
		}
	})

	t.Run("returns error when DNS resolver returns non-success rcode", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		server := &miekgdns.Server{
			PacketConn: pc,
			Handler: miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
				msg := new(miekgdns.Msg)
				msg.SetRcode(r, miekgdns.RcodeNameError)
				_ = w.WriteMsg(msg)
			}),
		}
		go func() { _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown(); _ = pc.Close() })

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.Resolvers = []string{pc.LocalAddr().String()}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		err = policy.CertificateAllowed(context.Background(), "api.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied for non-success rcode, got %v", err)
		}
	})

	t.Run("returns error when DNS resolver is unreachable", func(t *testing.T) {
		// Bind a UDP socket but never read from it so all queries time out.
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		t.Cleanup(func() { pc.Close() })

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.Resolvers = []string{pc.LocalAddr().String()}
		policy.dnsClient = &miekgdns.Client{Timeout: 100 * time.Millisecond}

		err = policy.CertificateAllowed(context.Background(), "api.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied for unreachable resolver, got %v", err)
		}
	})

	t.Run("returns error when hostname has no A or AAAA records", func(t *testing.T) {
		nameserver := startTestDNSServer(t, nil, nil)

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^api\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		err := policy.CertificateAllowed(context.Background(), "api.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied for hostname with no DNS records, got %v", err)
		}
	})

	t.Run("returns error on CNAME loop", func(t *testing.T) {
		nameserver := startTestDNSServer(t, nil, map[string]string{
			"a.example.com.": "b.example.com.",
			"b.example.com.": "a.example.com.",
		})

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^a\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		err := policy.CertificateAllowed(context.Background(), "a.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied for CNAME loop, got %v", err)
		}
	})

	t.Run("returns error when CNAME chain exceeds maximum depth", func(t *testing.T) {
		nameserver := startTestDNSServer(t, nil, map[string]string{
			"c1.example.com.": "c2.example.com.",
			"c2.example.com.": "c3.example.com.",
			"c3.example.com.": "c4.example.com.",
			"c4.example.com.": "c5.example.com.",
			"c5.example.com.": "c6.example.com.",
			"c6.example.com.": "c7.example.com.",
			"c7.example.com.": "c8.example.com.",
			"c8.example.com.": "c9.example.com.",
		})

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^c1\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		err := policy.CertificateAllowed(context.Background(), "c1.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied for CNAME chain depth exceeded, got %v", err)
		}
	})

	t.Run("allows when resolves_to target is a literal IP matching the hostname's resolved address", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"svc.example.com.": {netip.MustParseAddr("203.0.113.10")},
		}, nil)

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^svc\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"203.0.113.10"}
		policy.PermitLocal = true
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		if err := policy.CertificateAllowed(context.Background(), "svc.example.com"); err != nil {
			t.Fatalf("expected allow with literal IP resolves_to target, got %v", err)
		}
	})
}

func TestCheckResolvesTo(t *testing.T) {
	t.Run("passes when incoming chain name matches allowed member", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.ResolvesTo = []string{"proxy.example.com"}
		policy.resolvedTargets = &resolvedTargetsCache{
			members: map[string]struct{}{
				"proxy.example.com": {},
				"203.0.113.10":      {},
			},
			expiry: time.Now().Add(time.Hour),
			now:    time.Now,
		}

		// Incoming hostname CNAMEs to proxy.example.com but resolves to a different
		// IP (simulating geo-DNS). The CNAME name match should be sufficient.
		chain := &resolvedChain{
			names: []string{"svc.example.com", "proxy.example.com"},
			addrs: []netip.Addr{netip.MustParseAddr("203.0.113.99")},
		}

		if err := policy.checkResolvesTo(chain, policy.resolvedTargets.members); err != nil {
			t.Fatalf("expected allow via CNAME name match, got %v", err)
		}
	})

	t.Run("passes when incoming chain IP matches allowed member", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.ResolvesTo = []string{"target.internal"}
		policy.resolvedTargets = &resolvedTargetsCache{
			members: map[string]struct{}{
				"target.internal": {},
				"203.0.113.10":    {},
			},
			expiry: time.Now().Add(time.Hour),
			now:    time.Now,
		}

		chain := &resolvedChain{
			addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		}

		if err := policy.checkResolvesTo(chain, policy.resolvedTargets.members); err != nil {
			t.Fatalf("expected allow via IP match, got %v", err)
		}
	})

	t.Run("fails when no chain element matches allowed members", func(t *testing.T) {
		policy := newTestPolicy(t)
		policy.ResolvesTo = []string{"proxy.example.com"}
		policy.resolvedTargets = &resolvedTargetsCache{
			members: map[string]struct{}{
				"proxy.example.com": {},
				"203.0.113.10":      {},
			},
			expiry: time.Now().Add(time.Hour),
			now:    time.Now,
		}

		chain := &resolvedChain{
			names: []string{"svc.example.com", "other.example.com"},
			addrs: []netip.Addr{netip.MustParseAddr("203.0.113.99")},
		}

		err := policy.checkResolvesTo(chain, policy.resolvedTargets.members)
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
		}
	})
}

func TestCertificateAllowedCNAMEResolvesTo(t *testing.T) {
	t.Run("allows when incoming hostname CNAMEs to resolves_to target", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"proxy.example.com.": {netip.MustParseAddr("203.0.113.10")},
		}, map[string]string{
			"svc.example.com.": "proxy.example.com.",
		})

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^svc\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"proxy.example.com"}
		policy.PermitLocal = true
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		// svc.example.com → CNAME proxy.example.com → 203.0.113.10
		// target chain: names=["proxy.example.com"], addrs=[203.0.113.10]
		// incoming chain: names=["svc.example.com","proxy.example.com"], addrs=[203.0.113.10]
		// "proxy.example.com" is in allowed members → pass
		if err := policy.CertificateAllowed(context.Background(), "svc.example.com"); err != nil {
			t.Fatalf("expected allow via CNAME name match, got %v", err)
		}
	})

	t.Run("allows when incoming hostname and target share intermediate CNAME", func(t *testing.T) {
		// Both svc.example.com and proxy.example.com CNAME to cdn.shared.com.
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"cdn.shared.com.": {netip.MustParseAddr("203.0.113.50")},
		}, map[string]string{
			"proxy.example.com.": "cdn.shared.com.",
			"svc.example.com.":   "cdn.shared.com.",
		})

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^svc\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"proxy.example.com"}
		policy.PermitLocal = true
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		// target chain: names=["proxy.example.com","cdn.shared.com"], addrs=[203.0.113.50]
		// incoming chain: names=["svc.example.com","cdn.shared.com"], addrs=[203.0.113.50]
		// "cdn.shared.com" is in allowed members → pass
		if err := policy.CertificateAllowed(context.Background(), "svc.example.com"); err != nil {
			t.Fatalf("expected allow via shared intermediate CNAME, got %v", err)
		}
	})

	t.Run("denies when incoming hostname shares no chain element with resolves_to target", func(t *testing.T) {
		nameserver := startTestDNSServer(t, map[string][]netip.Addr{
			"proxy.example.com.": {netip.MustParseAddr("203.0.113.10")},
			"other.example.com.": {netip.MustParseAddr("203.0.113.99")},
		}, nil)

		policy := newTestPolicy(t)
		policy.AllowRegexp = []string{`^other\.example\.com$`}
		policy.allowRegexp = mustCompileRegexps(t, policy.AllowRegexp)
		policy.ResolvesTo = []string{"proxy.example.com"}
		policy.PermitLocal = true
		policy.Resolvers = []string{nameserver}
		policy.dnsClient = &miekgdns.Client{Timeout: 2 * time.Second}

		err := policy.CertificateAllowed(context.Background(), "other.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected permission denied, got %v", err)
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
