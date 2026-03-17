package rewrite

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const defaultCacheTTL = 30 * time.Second

type cachedResult struct {
	addr      netip.Addr
	expiresAt time.Time
}

// Resolver resolves rewrite targets to concrete IP addresses.
// It accepts CIDR strings, plain IPs, and hostnames.
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]cachedResult
	cacheTTL time.Duration
	lookupIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func NewResolver() *Resolver {
	return &Resolver{
		cache:    make(map[string]cachedResult),
		cacheTTL: defaultCacheTTL,
		lookupIP: net.DefaultResolver.LookupNetIP,
	}
}

func (r *Resolver) Resolve(ctx context.Context, rewriteTo string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(rewriteTo); err == nil {
		return prefix.Addr(), nil
	}
	if addr, err := netip.ParseAddr(rewriteTo); err == nil {
		return addr, nil
	}

	if addr, ok := r.lookupCached(rewriteTo); ok {
		return addr, nil
	}

	ips, err := r.lookupIP(ctx, "ip4", rewriteTo)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %s: %w", rewriteTo, err)
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: no IPv4 addresses found", rewriteTo)
	}

	addr := ips[0].Unmap()
	r.storeCached(rewriteTo, addr)
	return addr, nil
}

func (r *Resolver) lookupCached(host string) (netip.Addr, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.cache[host]
	if !ok || time.Now().After(entry.expiresAt) {
		return netip.Addr{}, false
	}
	return entry.addr, true
}

func (r *Resolver) storeCached(host string, addr netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[host] = cachedResult{
		addr:      addr,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
}
