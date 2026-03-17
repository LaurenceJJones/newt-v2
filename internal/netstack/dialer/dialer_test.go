package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type staticResolver struct {
	addrs []string
	err   error
}

func (r staticResolver) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return r.addrs, r.err
}

func TestFilterAddressesHonorsFamily(t *testing.T) {
	got := filterAddresses([]string{"192.0.2.10", "2001:db8::10"}, 443, true, false)
	if len(got) != 1 {
		t.Fatalf("expected 1 address, got %d", len(got))
	}
	if got[0] != netip.MustParseAddrPort("192.0.2.10:443") {
		t.Fatalf("unexpected address: %s", got[0])
	}
}

func TestDialContextUsesProtocolSpecificCallback(t *testing.T) {
	expected := &net.TCPConn{}
	called := false

	conn, err := DialContext(context.Background(), "tcp4", "example.com:443", Callbacks{
		Resolve: staticResolver{addrs: []string{"192.0.2.10"}},
		DialTCP: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			called = true
			if addr != netip.MustParseAddrPort("192.0.2.10:443") {
				t.Fatalf("unexpected addr: %s", addr)
			}
			return expected, nil
		},
		DialUDP: func(laddr, raddr netip.AddrPort) (net.Conn, error) {
			t.Fatal("unexpected udp dial")
			return nil, nil
		},
		DialPing: func(addr netip.Addr) (net.Conn, error) {
			t.Fatal("unexpected ping dial")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	if !called {
		t.Fatal("expected tcp dial callback")
	}
	if conn != expected {
		t.Fatal("unexpected connection returned")
	}
}

func TestDialContextReturnsNoSuitableAddressWhenFamiliesDontMatch(t *testing.T) {
	_, err := DialContext(context.Background(), "tcp4", "example.com:443", Callbacks{
		Resolve: staticResolver{addrs: []string{"2001:db8::10"}},
		DialTCP: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) { return nil, nil },
		DialUDP: func(laddr, raddr netip.AddrPort) (net.Conn, error) { return nil, nil },
		DialPing: func(addr netip.Addr) (net.Conn, error) { return nil, nil },
	})
	if err == nil {
		t.Fatal("expected error")
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("expected net.OpError, got %T", err)
	}
	if !errors.Is(opErr.Err, ErrNoSuitableAddress) {
		t.Fatalf("unexpected error: %v", err)
	}
}
