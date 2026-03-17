package packet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestRewriteDestinationIPv4(t *testing.T) {
	packet := makeUDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("192.168.0.10"),
		12345,
		8080,
		[]byte("hello"),
	)

	rewritten := RewriteDestination(packet, netip.MustParseAddr("127.0.0.1"))
	if rewritten == nil {
		t.Fatal("expected rewritten packet")
	}
	if &rewritten[0] == &packet[0] {
		t.Fatal("expected rewrite to copy the packet")
	}

	ipv4Header := header.IPv4(rewritten)
	if got := netip.AddrFrom4(ipv4Header.DestinationAddress().As4()); got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("unexpected destination: %s", got)
	}
}

func TestRewriteSourceIPv4(t *testing.T) {
	packet := makeUDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("192.168.0.10"),
		12345,
		8080,
		[]byte("hello"),
	)

	rewritten := RewriteSource(packet, netip.MustParseAddr("203.0.113.5"))
	if rewritten == nil {
		t.Fatal("expected rewritten packet")
	}

	ipv4Header := header.IPv4(rewritten)
	if got := netip.AddrFrom4(ipv4Header.SourceAddress().As4()); got != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("unexpected source: %s", got)
	}
}

func makeUDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	ipLen := header.IPv4MinimumSize
	udpLen := header.UDPMinimumSize + len(payload)
	packet := make([]byte, ipLen+udpLen)

	ipv4Header := header.IPv4(packet)
	ipv4Header.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())

	udpHeader := header.UDP(packet[ipLen:])
	udpHeader.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(packet[ipLen+header.UDPMinimumSize:], payload)

	xsum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		ipv4Header.SourceAddress(),
		ipv4Header.DestinationAddress(),
		uint16(udpLen),
	)
	xsum = checksum.Checksum(packet[ipLen:], xsum)
	udpHeader.SetChecksum(^xsum)

	return packet
}
