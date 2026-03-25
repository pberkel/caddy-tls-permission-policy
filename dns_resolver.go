package tlspermissionpolicy

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/caddyserver/caddy/v2/modules/caddytls"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ResolveAddrs resolves a hostname or literal IP into one or more IP addresses.
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

// CheckResolvesTo ensures the resolved name addresses match one of the configured targets.
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
