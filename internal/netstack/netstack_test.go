package netstack

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func TestPortRangeRoundTrip(t *testing.T) {
	ranges := []PortRange{
		{Min: 80, Max: 80, Protocol: "tcp"},
		{Min: 53, Max: 53, Protocol: "udp"},
	}

	got := fromRulePortRanges(toRulePortRanges(ranges))

	if len(got) != len(ranges) {
		t.Fatalf("expected %d ranges, got %d", len(ranges), len(got))
	}
	for i := range ranges {
		if got[i] != ranges[i] {
			t.Fatalf("range %d mismatch: got %#v want %#v", i, got[i], ranges[i])
		}
	}
}

func TestForwardingRulesReturnNetipTypes(t *testing.T) {
	tunDev, ns, err := CreateTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1280,
	)
	if err != nil {
		t.Fatalf("create tun: %v", err)
	}
	defer func() { _ = tunDev.Close() }()
	defer func() { _ = ns.Close() }()

	src := netip.MustParsePrefix("10.0.0.0/24")
	dst := netip.MustParsePrefix("192.168.0.0/24")
	ns.AddForwardingRule(src, dst, "example.internal", []PortRange{{Min: 443, Max: 443, Protocol: "tcp"}}, true)

	rules := ns.ForwardingRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].SourcePrefix != src {
		t.Fatalf("unexpected source prefix: %s", rules[0].SourcePrefix)
	}
	if rules[0].DestPrefix != dst {
		t.Fatalf("unexpected dest prefix: %s", rules[0].DestPrefix)
	}
	if !rules[0].DisableICMP {
		t.Fatal("expected DisableICMP to round-trip")
	}
	if rules[0].RewriteTo != "example.internal" {
		t.Fatalf("unexpected rewrite target: %q", rules[0].RewriteTo)
	}
	if len(rules[0].PortRanges) != 1 || rules[0].PortRanges[0].Protocol != "tcp" {
		t.Fatalf("unexpected port ranges: %#v", rules[0].PortRanges)
	}
}

func TestProtocolAddressForIPv4MappedReturnsIPv4(t *testing.T) {
	addr := netip.MustParseAddr("::ffff:192.0.2.10")

	normalized, proto, ok := protocolAddressFor(addr)
	if !ok {
		t.Fatal("expected address to be supported")
	}
	if normalized != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("unexpected normalized address: %s", normalized)
	}
	if proto != ipv4.ProtocolNumber {
		t.Fatalf("unexpected protocol: %v", proto)
	}
}

func TestProtocolAddressForIPv6ReturnsIPv6(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::10")

	normalized, proto, ok := protocolAddressFor(addr)
	if !ok {
		t.Fatal("expected address to be supported")
	}
	if normalized != addr {
		t.Fatalf("unexpected normalized address: %s", normalized)
	}
	if proto != ipv6.ProtocolNumber {
		t.Fatalf("unexpected protocol: %v", proto)
	}
}
