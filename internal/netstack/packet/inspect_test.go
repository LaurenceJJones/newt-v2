package packet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestParseIPv4UDP(t *testing.T) {
	raw := makeUDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("192.168.0.10"),
		12345,
		8080,
		[]byte("hello"),
	)

	parsed, ok := ParseIPv4(raw)
	if !ok {
		t.Fatal("expected udp packet to parse")
	}
	if parsed.SourceAddr != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("unexpected source: %s", parsed.SourceAddr)
	}
	if parsed.DestinationAddr != netip.MustParseAddr("192.168.0.10") {
		t.Fatalf("unexpected destination: %s", parsed.DestinationAddr)
	}
	if parsed.SourcePort != 12345 || parsed.DestinationPort != 8080 {
		t.Fatalf("unexpected ports: %d -> %d", parsed.SourcePort, parsed.DestinationPort)
	}
	if parsed.Protocol != header.UDPProtocolNumber {
		t.Fatalf("unexpected protocol: %d", parsed.Protocol)
	}
}

func TestParseIPv4RejectsShortPackets(t *testing.T) {
	if _, ok := ParseIPv4([]byte{0x45}); ok {
		t.Fatal("expected short packet rejection")
	}
}

func TestParseIPv4ICMPHasZeroPorts(t *testing.T) {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ipv4Header := header.IPv4(packet)
	ipv4Header.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(netip.MustParseAddr("10.0.0.1").As4()),
		DstAddr:     tcpip.AddrFrom4(netip.MustParseAddr("192.168.0.10").As4()),
	})
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())

	parsed, ok := ParseIPv4(packet)
	if !ok {
		t.Fatal("expected icmp packet to parse")
	}
	if parsed.SourcePort != 0 || parsed.DestinationPort != 0 {
		t.Fatalf("expected zero ports for icmp, got %d -> %d", parsed.SourcePort, parsed.DestinationPort)
	}
}
