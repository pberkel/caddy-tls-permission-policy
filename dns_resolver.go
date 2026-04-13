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
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"
	miekgdns "github.com/miekg/dns"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const maxCNAMEChainDepth = 8
const resolvedTargetsCacheTTL = 5 * time.Minute

// resolvedChain holds the full DNS resolution chain for a hostname: all names
// encountered during resolution (the initial query name plus each CNAME target)
// and the final resolved IP addresses. Names are normalized: lowercased with no
// trailing dot.
//
// When resolved via the system resolver, names is always empty because
// net.Resolver does not expose intermediate CNAME records.
type resolvedChain struct {
	names []string
	addrs []netip.Addr
}

// resolvedTargetsCache holds the resolved members of all configured resolves_to
// targets with a TTL-based expiry. Members is a mixed set of normalized hostname
// strings (collected from DNS name chains) and IP address strings, covering the
// full resolution chain of each configured target. Concurrent cache misses are
// coalesced via a singleflight group so that only one DNS resolution runs at a time.
type resolvedTargetsCache struct {
	mu      sync.RWMutex
	sf      singleflight.Group
	members map[string]struct{}
	expiry  time.Time
	now     func() time.Time
}

// resolveAddrs resolves a hostname or literal IP into a resolvedChain.
// earlyExit is an optional set of allowed members: when resolving via the
// custom DNS client, resolution stops as soon as a visited name is found in
// earlyExit, returning a partial chain with no addrs. Pass nil to always
// resolve to completion.
func (p *PermissionByPolicy) resolveAddrs(ctx context.Context, name string, earlyExit map[string]struct{}) (*resolvedChain, error) {
	if addr, err := netip.ParseAddr(name); err == nil {
		if c := p.debugCheck("resolved literal IP address"); c != nil {
			c.Write(zap.String("name", name), zap.String("ip", addr.String()))
		}
		return &resolvedChain{addrs: []netip.Addr{addr}}, nil
	}

	if p.dnsClient != nil {
		return p.resolveChainWithClient(ctx, name, earlyExit)
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
	if c := p.debugCheck("resolved hostname addresses"); c != nil {
		c.Write(zap.String("name", name), zap.Any("resolved_addrs", resolved))
	}

	return &resolvedChain{addrs: resolved}, nil
}

// resolveChainWithClient resolves a hostname using the configured resolvers list,
// collecting all DNS names encountered (the initial query name plus each CNAME
// target) and the final IP addresses into a resolvedChain. If earlyExit is
// non-nil, resolution stops as soon as a visited name is found in that set,
// returning a partial chain without addrs populated.
func (p *PermissionByPolicy) resolveChainWithClient(ctx context.Context, name string, earlyExit map[string]struct{}) (*resolvedChain, error) {
	questionName := miekgdns.Fqdn(name)
	chain := &resolvedChain{}
	resolved := make(map[netip.Addr]struct{})
	seenNames := make(map[string]struct{}, maxCNAMEChainDepth)
	var lastErr error
	var cnameTarget string

	for depth := 0; depth < maxCNAMEChainDepth; depth++ {
		if _, seen := seenNames[questionName]; seen {
			return nil, fmt.Errorf("resolving %q with configured resolver(s): detected CNAME loop at %q", name, strings.TrimSuffix(questionName, "."))
		}
		seenNames[questionName] = struct{}{}
		normalizedName := strings.TrimSuffix(questionName, ".")
		chain.names = append(chain.names, normalizedName)

		// If the current name already matches an allowed target, there is no need
		// to issue further DNS queries. Return the partial chain; checkResolvesTo
		// will find the matching name and allow the request.
		if _, ok := earlyExit[normalizedName]; ok {
			return chain, nil
		}

		cnameTarget = ""
		clear(resolved)

		// Query each configured resolver for A and AAAA records, stopping at the
		// first resolver that returns results. If a resolver returns a CNAME instead
		// of A/AAAA records, the CNAME target is recorded and the outer loop follows
		// it on the next iteration.
		for _, resolver := range p.Resolvers {
			for _, qtype := range []uint16{miekgdns.TypeA, miekgdns.TypeAAAA} {
				msg := &miekgdns.Msg{}
				msg.SetQuestion(questionName, qtype)

				response, _, err := p.dnsClient.ExchangeContext(ctx, msg, resolver)
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
			if len(resolved) > 0 {
				break
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
			return nil, fmt.Errorf("resolving %q with configured resolver(s): %w", name, lastErr)
		}
		return nil, fmt.Errorf("%w: domain did not resolve to any IP addresses", caddytls.ErrPermissionDenied)
	}

	chain.addrs = make([]netip.Addr, 0, len(resolved))
	for addr := range resolved {
		chain.addrs = append(chain.addrs, addr)
	}
	if c := p.debugCheck("resolved hostname addresses"); c != nil {
		c.Write(
			zap.String("name", name),
			zap.Any("resolved_addrs", chain.addrs),
			zap.Strings("resolvers", append([]string(nil), p.Resolvers...)),
			zap.Bool("custom_resolver", true),
		)
	}

	return chain, nil
}

// checkResolvesTo ensures the resolved name chain shares at least one member
// with the set of allowed target members. A match on any chain element —
// either an intermediate DNS name or a final IP address — is sufficient.
// This allows matching across geo-DNS boundaries: if the incoming hostname
// and a resolves_to target share a common intermediate CNAME (e.g. a CDN
// hostname), the check passes even if their final IPs differ.
func (p *PermissionByPolicy) checkResolvesTo(chain *resolvedChain, allowed map[string]struct{}) error {
	if c := p.debugCheck("evaluated resolves_to targets"); c != nil {
		c.Write(
			zap.Strings("resolved_names", chain.names),
			zap.Any("resolved_addrs", chain.addrs),
			zap.Any("allowed_members", allowed),
		)
	}

	if len(chain.names) == 0 && len(chain.addrs) == 0 {
		return fmt.Errorf("%w: no resolved addresses to validate against resolves_to", caddytls.ErrPermissionDenied)
	}

	for _, name := range chain.names {
		if _, ok := allowed[name]; ok {
			return nil
		}
	}
	for _, addr := range chain.addrs {
		if _, ok := allowed[addr.String()]; ok {
			return nil
		}
	}

	return fmt.Errorf("%w: domain did not resolve to any configured resolves_to target", caddytls.ErrPermissionDenied)
}

// allowedTargetMembers returns the cached set of allowed target members, resolving
// all ResolvesTo targets if the cache is absent or expired. Concurrent cache misses are
// coalesced via a singleflight group so that only one resolution runs at a time.
func (p *PermissionByPolicy) allowedTargetMembers(ctx context.Context) (map[string]struct{}, error) {
	cache := p.resolvedTargets

	// Fast path: valid cache entry.
	cache.mu.RLock()
	if cache.members != nil && cache.now().Before(cache.expiry) {
		members := cache.members
		cache.mu.RUnlock()
		return members, nil
	}
	cache.mu.RUnlock()

	// Coalesce concurrent cache misses: only one goroutine resolves at a time;
	// the rest wait and share the result.
	v, err, _ := cache.sf.Do("resolve", func() (any, error) {
		// Double-check under write lock: a previous flight may have already refreshed.
		cache.mu.Lock()
		if cache.members != nil && cache.now().Before(cache.expiry) {
			members := cache.members
			cache.mu.Unlock()
			return members, nil
		}
		cache.mu.Unlock()

		// Resolve all targets outside the lock so readers are not blocked during DNS I/O.
		// Targets are always resolved to completion (nil earlyExit) to build the full
		// members set used by checkResolvesTo and earlyExit for incoming hostnames.
		members := make(map[string]struct{})
		for _, target := range p.ResolvesTo {
			chain, err := p.resolveAddrs(ctx, target, nil)
			if err != nil {
				return nil, fmt.Errorf("%w: resolving resolves_to target %q: %w", caddytls.ErrPermissionDenied, target, err)
			}
			for _, name := range chain.names {
				members[name] = struct{}{}
			}
			for _, addr := range chain.addrs {
				members[addr.String()] = struct{}{}
			}
		}

		// Store result under write lock.
		cache.mu.Lock()
		cache.members = members
		cache.expiry = cache.now().Add(resolvedTargetsCacheTTL)
		cache.mu.Unlock()
		return members, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]struct{}), nil
}
