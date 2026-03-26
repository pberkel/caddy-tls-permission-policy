package tlspermissionpolicy

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
)

func TestProvision(t *testing.T) {
	t.Run("fails when no policy knob is configured", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = -1
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
		policy.MaxCertsPerDomain = 1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.DenyRegexp = []string{`^blocked\.example\.com$`}
		policy.approvals = &approvalState{
			atCapacityDomains: map[string]time.Time{"example.com": time.Now().Add(time.Minute)},
			now:               time.Now,
		}

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
		if len(policy.approvals.atCapacityDomains) != 0 {
			t.Fatalf("expected approval cache reset after first provision, got %d entries", len(policy.approvals.atCapacityDomains))
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
		if len(policy.approvals.atCapacityDomains) != 0 {
			t.Fatalf("expected approval cache reset after reprovision, got %d entries", len(policy.approvals.atCapacityDomains))
		}
	})

	t.Run("fails when nameserver is not in host:port form", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.MaxCertsPerDomain = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.Nameserver = []string{"203.0.113.12"}
		ctx, cancel := newProvisionContext(t)
		defer cancel()

		err := policy.Provision(ctx)
		if err == nil {
			t.Fatal("expected provision error, got nil")
		}
	})

	t.Run("configures custom dns client timeout when nameserver is set", func(t *testing.T) {
		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.MaxCertsPerDomain = -1
		policy.AllowRegexp = []string{`^.*\.example\.com$`}
		policy.Nameserver = []string{"203.0.113.12:53"}
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
		nameserver 203.0.113.12:53
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
	if len(policy.Nameserver) != 1 {
		t.Fatalf("expected 1 nameserver entry, got %d", len(policy.Nameserver))
	}
	if policy.PermitAll {
		t.Fatal("expected permit_all to be false")
	}
}

func TestUnmarshalCaddyfileRateLimitStoresRawValues(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		rate_limit 100 1h
		per_domain_rate_limit 5 24h
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if policy.GlobalRateLimit == nil {
		t.Fatal("expected GlobalRateLimit to be set")
	}
	if policy.GlobalRateLimit.limitRaw != "100" {
		t.Errorf("expected GlobalRateLimit.limitRaw=%q, got %q", "100", policy.GlobalRateLimit.limitRaw)
	}
	if policy.GlobalRateLimit.durationRaw != "1h" {
		t.Errorf("expected GlobalRateLimit.durationRaw=%q, got %q", "1h", policy.GlobalRateLimit.durationRaw)
	}

	if policy.PerDomainRateLimit == nil {
		t.Fatal("expected PerDomainRateLimit to be set")
	}
	if policy.PerDomainRateLimit.limitRaw != "5" {
		t.Errorf("expected PerDomainRateLimit.limitRaw=%q, got %q", "5", policy.PerDomainRateLimit.limitRaw)
	}
	if policy.PerDomainRateLimit.durationRaw != "24h" {
		t.Errorf("expected PerDomainRateLimit.durationRaw=%q, got %q", "24h", policy.PerDomainRateLimit.durationRaw)
	}
}

func TestUnmarshalCaddyfileRateLimitStoresPlaceholderValues(t *testing.T) {
	policy := &PermissionByPolicy{}
	dispenser := caddyfile.NewTestDispenser(`
	permission {
		rate_limit {env.RATE_LIMIT} {env.RATE_LIMIT_DURATION}
		per_domain_rate_limit {env.DOMAIN_RATE_LIMIT} {env.DOMAIN_RATE_LIMIT_DURATION}
	}
	`)

	if err := policy.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if policy.GlobalRateLimit == nil {
		t.Fatal("expected GlobalRateLimit to be set")
	}
	if policy.GlobalRateLimit.limitRaw != "{env.RATE_LIMIT}" {
		t.Errorf("expected raw placeholder to be stored, got %q", policy.GlobalRateLimit.limitRaw)
	}
	if policy.GlobalRateLimit.durationRaw != "{env.RATE_LIMIT_DURATION}" {
		t.Errorf("expected raw placeholder to be stored, got %q", policy.GlobalRateLimit.durationRaw)
	}
}

func TestProvisionReplacesRateLimitPlaceholders(t *testing.T) {
	t.Setenv("TEST_RATE_LIMIT", "10")
	t.Setenv("TEST_RATE_LIMIT_DURATION", "1h")
	t.Setenv("TEST_DOMAIN_RATE_LIMIT", "3")
	t.Setenv("TEST_DOMAIN_RATE_LIMIT_DURATION", "24h")

	policy := &PermissionByPolicy{}
	policy.MaxSubdomainDepth = -1
	policy.MaxCertsPerDomain = -1
	policy.GlobalRateLimit = &RateLimit{
		limitRaw:    "{env.TEST_RATE_LIMIT}",
		durationRaw: "{env.TEST_RATE_LIMIT_DURATION}",
	}
	policy.PerDomainRateLimit = &RateLimit{
		limitRaw:    "{env.TEST_DOMAIN_RATE_LIMIT}",
		durationRaw: "{env.TEST_DOMAIN_RATE_LIMIT_DURATION}",
	}

	ctx, cancel := newProvisionContext(t)
	defer cancel()

	if err := policy.Provision(ctx); err != nil {
		t.Fatalf("expected provision success, got %v", err)
	}
	if policy.GlobalRateLimit.Limit != 10 {
		t.Errorf("expected GlobalRateLimit.Limit=10, got %d", policy.GlobalRateLimit.Limit)
	}
	if time.Duration(policy.GlobalRateLimit.Duration) != time.Hour {
		t.Errorf("expected GlobalRateLimit.Duration=1h, got %v", time.Duration(policy.GlobalRateLimit.Duration))
	}
	if policy.PerDomainRateLimit.Limit != 3 {
		t.Errorf("expected PerDomainRateLimit.Limit=3, got %d", policy.PerDomainRateLimit.Limit)
	}
	if time.Duration(policy.PerDomainRateLimit.Duration) != 24*time.Hour {
		t.Errorf("expected PerDomainRateLimit.Duration=24h, got %v", time.Duration(policy.PerDomainRateLimit.Duration))
	}
}

func TestProvisionFailsOnInvalidRateLimitPlaceholderValues(t *testing.T) {
	t.Run("invalid limit after replacement", func(t *testing.T) {
		t.Setenv("TEST_BAD_LIMIT", "notanint")

		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.MaxCertsPerDomain = -1
		policy.GlobalRateLimit = &RateLimit{
			limitRaw:    "{env.TEST_BAD_LIMIT}",
			durationRaw: "1h",
		}

		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for invalid limit, got nil")
		}
	})

	t.Run("invalid duration after replacement", func(t *testing.T) {
		t.Setenv("TEST_BAD_DURATION", "notaduration")

		policy := &PermissionByPolicy{}
		policy.MaxSubdomainDepth = -1
		policy.MaxCertsPerDomain = -1
		policy.GlobalRateLimit = &RateLimit{
			limitRaw:    "5",
			durationRaw: "{env.TEST_BAD_DURATION}",
		}

		ctx, cancel := newProvisionContext(t)
		defer cancel()

		if err := policy.Provision(ctx); err == nil {
			t.Fatal("expected provision error for invalid duration, got nil")
		}
	})
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

func newProvisionContext(t *testing.T) (caddy.Context, context.CancelFunc) {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	setCaddyContextStorage(t, &ctx, &certmagic.FileStorage{Path: t.TempDir()})
	return ctx, cancel
}

func setCaddyContextStorage(t *testing.T, ctx *caddy.Context, storage certmagic.Storage) {
	t.Helper()

	ctxValue := reflect.ValueOf(ctx).Elem()
	cfgField := ctxValue.FieldByName("cfg")
	cfgPtrType := cfgField.Type()
	cfgValue := reflect.New(cfgPtrType.Elem())
	storageField := cfgValue.Elem().FieldByName("storage")

	reflect.NewAt(storageField.Type(), unsafe.Pointer(storageField.UnsafeAddr())).Elem().Set(reflect.ValueOf(storage))
	reflect.NewAt(cfgField.Type(), unsafe.Pointer(cfgField.UnsafeAddr())).Elem().Set(cfgValue)
}
