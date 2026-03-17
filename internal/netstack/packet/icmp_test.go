package packet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestBuildICMPEchoReply(t *testing.T) {
	packet := BuildICMPEchoReply(
		netip.MustParseAddr("192.168.0.20"),
		netip.MustParseAddr("10.0.0.2"),
		123,
		7,
		[]byte("payload"),
	)
	if packet == nil {
		t.Fatal("expected packet")
	}

	ipHdr := header.IPv4(packet)
	if got := netip.AddrFrom4(ipHdr.SourceAddress().As4()); got != netip.MustParseAddr("192.168.0.20") {
		t.Fatalf("unexpected source: %s", got)
	}
	if got := netip.AddrFrom4(ipHdr.DestinationAddress().As4()); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("unexpected destination: %s", got)
	}
	if got := ipHdr.TransportProtocol(); got != header.ICMPv4ProtocolNumber {
		t.Fatalf("unexpected protocol: %d", got)
	}

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	if icmpHdr.Type() != header.ICMPv4EchoReply {
		t.Fatalf("unexpected icmp type: %d", icmpHdr.Type())
	}
	if icmpHdr.Ident() != 123 || icmpHdr.Sequence() != 7 {
		t.Fatalf("unexpected icmp echo fields: ident=%d seq=%d", icmpHdr.Ident(), icmpHdr.Sequence())
	}
}
