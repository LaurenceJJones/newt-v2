package rewrite

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestResolveParsesPrefixAndAddrDirectly(t *testing.T) {
	r := NewResolver()

	addr, err := r.Resolve(context.Background(), "192.168.1.10/32")
	if err != nil {
		t.Fatalf("resolve prefix: %v", err)
	}
	if addr != netip.MustParseAddr("192.168.1.10") {
		t.Fatalf("unexpected prefix addr: %s", addr)
	}

	addr, err = r.Resolve(context.Background(), "192.168.1.20")
	if err != nil {
		t.Fatalf("resolve addr: %v", err)
	}
	if addr != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("unexpected addr: %s", addr)
	}
}

func TestResolveCachesHostnameLookups(t *testing.T) {
	r := NewResolver()
	r.cacheTTL = time.Minute

	lookups := 0
	r.lookupIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}

	for range 2 {
		addr, err := r.Resolve(context.Background(), "example.internal")
		if err != nil {
			t.Fatalf("resolve hostname: %v", err)
		}
		if addr != netip.MustParseAddr("10.0.0.5") {
			t.Fatalf("unexpected resolved addr: %s", addr)
		}
	}

	if lookups != 1 {
		t.Fatalf("expected 1 lookup, got %d", lookups)
	}
}
