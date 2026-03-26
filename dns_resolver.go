package tlspermissionpolicy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
	miekgdns "github.com/miekg/dns"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const maxCNAMEChainDepth = 8

// ResolveAddrs resolves a hostname or literal IP into one or more IP addresses.
func (p *PermissionByPolicy) resolveAddrs(ctx context.Context, name string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(name); err == nil {
		if c := p.logger.Check(zapcore.DebugLevel, "resolved literal IP address"); c != nil {
			c.Write(zap.String("name", name), zap.String("ip", addr.String()))
		}
		return []netip.Addr{addr}, nil
	}

	if p.dnsClient != nil {
		return p.resolveAddrsWithClient(ctx, name)
	}

	resolved, err := p.lookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", name, err)
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("%w: domain did not resolve to any IP addresses", caddytls.ErrPermissionDenied)
	}
	for i, addr := range resolved {
		resolved[i] = addr.Unmap()
	}
	if c := p.logger.Check(zapcore.DebugLevel, "resolved hostname addresses"); c != nil {
		c.Write(zap.String("name", name), zap.Any("resolved_addrs", resolved))
	}

	return resolved, nil
}

// ResolveAddrsWithClient resolves a hostname using the configured nameserver list.
func (p *PermissionByPolicy) resolveAddrsWithClient(ctx context.Context, name string) ([]netip.Addr, error) {
	questionName := miekgdns.Fqdn(name)
	resolved := make(map[netip.Addr]struct{})
	seenNames := make(map[string]struct{}, maxCNAMEChainDepth)
	var lastErr error
	var cnameTarget string

	for depth := 0; depth < maxCNAMEChainDepth; depth++ {
		if _, seen := seenNames[questionName]; seen {
			return nil, fmt.Errorf("resolving %q with configured nameserver(s): detected CNAME loop at %q", name, strings.TrimSuffix(questionName, "."))
		}
		seenNames[questionName] = struct{}{}

		cnameTarget = ""
		resolved = make(map[netip.Addr]struct{})

		for _, nameserver := range p.Nameserver {
			for _, qtype := range []uint16{miekgdns.TypeA, miekgdns.TypeAAAA} {
				msg := &miekgdns.Msg{}
				msg.SetQuestion(questionName, qtype)

				response, _, err := p.dnsClient.ExchangeContext(ctx, msg, nameserver)
				if err != nil {
					lastErr = err
					continue
				}
				if response != nil && response.Rcode != miekgdns.RcodeSuccess {
					lastErr = fmt.Errorf("dns query returned rcode %s", miekgdns.RcodeToString[response.Rcode])
					continue
				}

				for _, answer := range response.Answer {
					switch rr := answer.(type) {
					case *miekgdns.A:
						if addr, ok := netip.AddrFromSlice(rr.A); ok {
							resolved[addr.Unmap()] = struct{}{}
						}
					case *miekgdns.AAAA:
						if addr, ok := netip.AddrFromSlice(rr.AAAA); ok {
							resolved[addr.Unmap()] = struct{}{}
						}
					case *miekgdns.CNAME:
						if cnameTarget == "" {
							cnameTarget = rr.Target
						}
					}
				}
			}
		}

		if len(resolved) > 0 {
			break
		}
		if cnameTarget == "" {
			break
		}

		questionName = miekgdns.Fqdn(cnameTarget)
	}

	if cnameTarget != "" && len(resolved) == 0 && lastErr == nil {
		return nil, fmt.Errorf("resolving %q: CNAME chain exceeds maximum depth of %d", name, maxCNAMEChainDepth)
	}

	if len(resolved) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("resolving %q with configured nameserver(s): %w", name, lastErr)
		}
		return nil, fmt.Errorf("%w: domain did not resolve to any IP addresses", caddytls.ErrPermissionDenied)
	}

	addrs := make([]netip.Addr, 0, len(resolved))
	for addr := range resolved {
		addrs = append(addrs, addr)
	}
	if c := p.logger.Check(zapcore.DebugLevel, "resolved hostname addresses"); c != nil {
		c.Write(
			zap.String("name", name),
			zap.Any("resolved_addrs", addrs),
			zap.Strings("nameservers", append([]string(nil), p.Nameserver...)),
			zap.Bool("custom_resolver", true),
		)
	}

	return addrs, nil
}

// CheckResolvesTo ensures the resolved name addresses match one of the configured targets.
func (p *PermissionByPolicy) checkResolvesTo(ctx context.Context, resolved []netip.Addr) error {
	allowedTargets, err := p.allowedTargetAddrs(ctx)
	if err != nil {
		return err
	}
	if c := p.logger.Check(zapcore.DebugLevel, "evaluated resolves_to targets"); c != nil {
		c.Write(
			zap.Any("resolved_addrs", resolved),
			zap.Any("allowed_targets", allowedTargets),
		)
	}

	if len(resolved) == 0 {
		return fmt.Errorf("%w: no resolved addresses to validate against resolves_to", caddytls.ErrPermissionDenied)
	}

	for _, addr := range resolved {
		if _, ok := allowedTargets[addr]; !ok {
			return fmt.Errorf("%w: domain resolved to disallowed target %s", caddytls.ErrPermissionDenied, addr)
		}
	}

	return nil
}

// allowedTargetAddrs returns the cached set of allowed target IP addresses, resolving
// all ResolvesTo targets if the cache is absent or expired.
func (p *PermissionByPolicy) allowedTargetAddrs(ctx context.Context) (map[netip.Addr]struct{}, error) {
	cache := p.resolvedTargets

	// Fast path: valid cache entry.
	cache.mu.RLock()
	if cache.addrs != nil && cache.now().Before(cache.expiry) {
		addrs := cache.addrs
		cache.mu.RUnlock()
		return addrs, nil
	}
	cache.mu.RUnlock()

	// Double-check under write lock before committing to resolution.
	cache.mu.Lock()
	if cache.addrs != nil && cache.now().Before(cache.expiry) {
		addrs := cache.addrs
		cache.mu.Unlock()
		return addrs, nil
	}
	cache.mu.Unlock()

	// Resolve all targets outside the lock so readers are not blocked during DNS I/O.
	// Multiple goroutines may resolve concurrently after a cache miss; this is safe
	// since the final update is guarded and DNS results for stable targets are identical.
	addrs := make(map[netip.Addr]struct{})
	for _, target := range p.ResolvesTo {
		targetAddrs, err := p.resolveAddrs(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("%w: resolving resolves_to target %q: %v", caddytls.ErrPermissionDenied, target, err)
		}
		for _, addr := range targetAddrs {
			addrs[addr.Unmap()] = struct{}{}
		}
	}

	// Store result under write lock, but only if the cache is still stale — another
	// goroutine may have completed resolution and written a fresh entry while we were resolving.
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.addrs == nil || !cache.now().Before(cache.expiry) {
		cache.addrs = addrs
		cache.expiry = cache.now().Add(resolvedTargetsCacheTTL)
	}
	return cache.addrs, nil
}
