// Copyright 2026 Pieter Berkel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestProvision(t *testing.T) {
	t.Run("fails when no policy knob is configured", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		err := policy.Provision(ctx)
		if err == nil {
			t.Fatal("expected provision error, got nil")
		}
	})

	t.Run("allows empty policy when permit_all is true", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.PermitAll = true
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only permit_ip enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.PermitIP = true
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only permit_local enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.PermitLocal = true
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only allow_regexp enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only deny_regexp enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only allow_subdomain enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowSubdomain = []string{"www"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("allows config with only deny_subdomain enabled", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.DenySubdomain = []string{"blocked"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
	})

	t.Run("normalizes allow_subdomain values to lowercase in provision", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowSubdomain = []string{"WWW"}
		ctx, cancel := newProvisionContext(t)
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
		policy.MaxSubdomainDepth = -1
		policy.DenySubdomain = []string{"BLOCKED"}
		ctx, cancel := newProvisionContext(t)
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
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}

		ctx, cancel := newProvisionContext(t)
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

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected second provision success, got %v", err)
		}
		if len(policy.allowRegexp) != 1 {
			t.Fatalf("expected 1 compiled allow regexp after reprovision, got %d", len(policy.allowRegexp))
		}
		if len(policy.denyRegexp) != 1 {
			t.Fatalf("expected 1 compiled deny regexp after reprovision, got %d", len(policy.denyRegexp))
		}
	})

	t.Run("defaults to port 53 when resolver has no port", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.Resolvers = []string{"203.0.113.12"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
		if policy.Resolvers[0] != "203.0.113.12:53" {
			t.Fatalf("expected resolver normalised to 203.0.113.12:53, got %s", policy.Resolvers[0])
		}
	})

	t.Run("configures custom dns client timeout when resolvers is set", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.Resolvers = []string{"203.0.113.12:53"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err != nil {
			t.Fatalf("expected provision success, got %v", err)
		}
		if policy.dnsClient == nil {
			t.Fatal("expected dns client to be configured")
		}
		if policy.dnsClient.Timeout != customDNSTimeout {
			t.Fatalf("expected dns timeout %v, got %v", customDNSTimeout, policy.dnsClient.Timeout)
		}
	})

	t.Run("fails when max_subdomain_depth is below -1", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -2
		policy.PermitAll = true
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for max_subdomain_depth < -1, got nil")
		}
	})

	t.Run("fails when allow_regexp contains an invalid pattern", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{"[invalid"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for invalid allow_regexp, got nil")
		}
	})

	t.Run("fails when deny_regexp contains an invalid pattern", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.DenyRegexp = []string{"[invalid"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for invalid deny_regexp, got nil")
		}
	})

	t.Run("fails when resolver host is empty", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.Resolvers = []string{":53"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for empty resolver host, got nil")
		}
	})

	t.Run("fails when resolver port is invalid", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.Resolvers = []string{"203.0.113.10:0"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for invalid resolver port, got nil")
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
		resolvers 203.0.113.12:53
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
	if len(policy.Resolvers) != 1 {
		t.Fatalf("expected 1 resolvers entry, got %d", len(policy.Resolvers))
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

func TestUnmarshalCaddyfileMaxSubdomainDepthStoresRawValue(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		max_subdomain_depth 3
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if policy.MaxSubdomainDepthRaw != "3" {
		t.Errorf("expected maxSubdomainDepthRaw=%q, got %q", "3", policy.MaxSubdomainDepthRaw)
	}
	// MaxSubdomainDepth should not be parsed until Provision resolves the raw value.
	if policy.MaxSubdomainDepth != 0 {
		t.Errorf("expected MaxSubdomainDepth to remain zero, got %d", policy.MaxSubdomainDepth)
	}
}

func TestUnmarshalCaddyfileMaxSubdomainDepthStoresPlaceholderValue(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		max_subdomain_depth {env.MAX_DEPTH}
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if policy.MaxSubdomainDepthRaw != "{env.MAX_DEPTH}" {
		t.Errorf("expected raw placeholder to be stored, got %q", policy.MaxSubdomainDepthRaw)
	}
}

func TestProvisionReplacesMaxSubdomainDepthPlaceholder(t *testing.T) {
	t.Setenv("TEST_MAX_DEPTH", "2")

	policy := &PermissionByPolicy{}
	policy.MaxSubdomainDepthRaw = "{env.TEST_MAX_DEPTH}"

	ctx, cancel := newProvisionContext(t)
	defer cancel()

	if err := policy.Provision(ctx); err != nil {
		t.Fatalf("expected provision success, got %v", err)
	}
	if policy.MaxSubdomainDepth != 2 {
		t.Errorf("expected MaxSubdomainDepth=2, got %d", policy.MaxSubdomainDepth)
	}
}

func TestProvisionFailsOnInvalidMaxSubdomainDepthPlaceholderValue(t *testing.T) {
	t.Setenv("TEST_BAD_MAX_DEPTH", "notanint")

	policy := &PermissionByPolicy{}
	policy.MaxSubdomainDepthRaw = "{env.TEST_BAD_MAX_DEPTH}"

	ctx, cancel := newProvisionContext(t)
	defer cancel()

	if err := policy.Provision(ctx); err == nil {
		t.Fatal("expected provision error for invalid max_subdomain_depth, got nil")
	}
}

func TestUnmarshalCaddyfileFailsOnMissingValue(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		allow_regexp
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("expected error for missing config value, got nil")
	}
}

func TestUnmarshalCaddyfileFailsOnUnrecognizedParameter(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		unknown_key value
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("expected error for unrecognized parameter, got nil")
	}
}

func TestUnmarshalCaddyfileBlockSyntaxForMultipleValues(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		allow_regexp {
			^api\.example\.com$
			^www\.example\.com$
		}
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(policy.AllowRegexp) != 2 {
		t.Fatalf("expected 2 allow_regexp entries from block syntax, got %d", len(policy.AllowRegexp))
	}
}

func newProvisionContext(t *testing.T) (caddy.Context, context.CancelFunc) {
	t.Helper()
	return caddy.NewContext(caddy.Context{Context: context.Background()})
}
