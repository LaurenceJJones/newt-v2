package ping

import (
	"net/netip"
	"testing"
)

func TestAddrNetwork(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
		want string
	}{
		{name: "ipv4", addr: netip.MustParseAddr("192.0.2.10"), want: "ping4"},
		{name: "ipv6", addr: netip.MustParseAddr("2001:db8::10"), want: "ping6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AddrFrom(tt.addr).Network(); got != tt.want {
				t.Fatalf("unexpected network: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestAddrFromPreservesAddr(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.10")
	if got := AddrFrom(addr).Addr(); got != addr {
		t.Fatalf("unexpected addr: got %s want %s", got, addr)
	}
}
