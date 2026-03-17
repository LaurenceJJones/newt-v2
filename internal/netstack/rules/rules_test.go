package rules

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestLookupMatchHonorsPortsAndProtocol(t *testing.T) {
	l := NewLookup()
	l.Add(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
		"",
		[]PortRange{{Min: 443, Max: 443, Protocol: "tcp"}},
		false,
	)

	match := l.Match(
		netip.MustParseAddr("10.0.0.10"),
		netip.MustParseAddr("192.168.0.99"),
		443,
		header.TCPProtocolNumber,
	)
	if match == nil {
		t.Fatal("expected tcp rule match")
	}

	noMatch := l.Match(
		netip.MustParseAddr("10.0.0.10"),
		netip.MustParseAddr("192.168.0.99"),
		443,
		header.UDPProtocolNumber,
	)
	if noMatch != nil {
		t.Fatalf("expected udp mismatch, got %#v", noMatch)
	}
}

func TestLookupRemoveUsesCanonicalPrefixes(t *testing.T) {
	l := NewLookup()
	l.Add(
		netip.MustParsePrefix("10.0.0.5/24"),
		netip.MustParsePrefix("192.168.0.77/24"),
		"rewrite",
		nil,
		true,
	)

	l.Remove(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
	)

	if rules := l.All(); len(rules) != 0 {
		t.Fatalf("expected rules to be removed canonically, got %#v", rules)
	}
}

func TestLookupMatchAllowsICMPWhenEnabled(t *testing.T) {
	l := NewLookup()
	l.Add(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
		"",
		nil,
		false,
	)

	match := l.Match(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("192.168.0.1"),
		0,
		header.ICMPv4ProtocolNumber,
	)
	if match == nil {
		t.Fatal("expected icmp match")
	}
}
