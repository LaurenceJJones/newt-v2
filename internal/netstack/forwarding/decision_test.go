package forwarding

import (
	"context"
	"net/netip"
	"testing"

	netpacket "github.com/fosrl/newt/internal/netstack/packet"
	"github.com/fosrl/newt/internal/netstack/rewrite"
	"github.com/fosrl/newt/internal/netstack/rules"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type staticResolver struct {
	addr netip.Addr
	err  error
}

func (r staticResolver) Resolve(ctx context.Context, rewriteTo string) (netip.Addr, error) {
	return r.addr, r.err
}

func TestPlanInboundDropsWithoutRule(t *testing.T) {
	lookup := rules.NewLookup()
	state := rewrite.NewState()
	packet, parsed := udpPacketForTest(t)

	decision, err := PlanInbound(context.Background(), packet, parsed, lookup, state, staticResolver{})
	if err != nil {
		t.Fatalf("plan inbound: %v", err)
	}
	if decision.Action != ActionDrop {
		t.Fatalf("expected drop, got %v", decision.Action)
	}
}

func TestPlanInboundRewritesNonLoopbackDestination(t *testing.T) {
	lookup := rules.NewLookup()
	lookup.Add(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
		"service.internal",
		nil,
		false,
	)
	state := rewrite.NewState()
	packet, parsed := udpPacketForTest(t)

	decision, err := PlanInbound(context.Background(), packet, parsed, lookup, state, staticResolver{addr: netip.MustParseAddr("203.0.113.10")})
	if err != nil {
		t.Fatalf("plan inbound: %v", err)
	}
	if decision.Action != ActionInject {
		t.Fatalf("expected inject, got %v", decision.Action)
	}

	rewritten, ok := netpacket.ParseIPv4(decision.Packet)
	if !ok {
		t.Fatal("expected rewritten packet to parse")
	}
	if rewritten.DestinationAddr != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("unexpected rewritten destination: %s", rewritten.DestinationAddr)
	}
}

func TestPlanInboundPreservesLoopbackRewriteForHandlerLookup(t *testing.T) {
	lookup := rules.NewLookup()
	lookup.Add(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
		"localhost",
		nil,
		false,
	)
	state := rewrite.NewState()
	packet, parsed := udpPacketForTest(t)

	decision, err := PlanInbound(context.Background(), packet, parsed, lookup, state, staticResolver{addr: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatalf("plan inbound: %v", err)
	}
	if decision.Action != ActionInject {
		t.Fatalf("expected inject, got %v", decision.Action)
	}
	if string(decision.Packet) != string(packet) {
		t.Fatal("expected loopback rewrite to preserve original packet bytes")
	}
	if got, ok := state.DestinationRewrite(parsed.SourceAddr.String(), parsed.DestinationAddr.String(), parsed.DestinationPort, uint8(parsed.Protocol)); !ok || got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("expected loopback rewrite state to be remembered, got %v %v", got, ok)
	}
}

func TestPlanOutboundReverseTranslatesSource(t *testing.T) {
	state := rewrite.NewState()
	originalDst := netip.MustParseAddr("192.168.0.20")
	rewrittenTo := netip.MustParseAddr("127.0.0.1")
	state.RememberConnection("10.0.0.2", 12000, originalDst.String(), 8080, uint8(header.UDPProtocolNumber), originalDst, rewrittenTo)

	packet := makeForwardingUDPPacket(
		rewrittenTo,
		netip.MustParseAddr("10.0.0.2"),
		8080,
		12000,
		[]byte("reply"),
	)
	parsed, ok := netpacket.ParseIPv4(packet)
	if !ok {
		t.Fatal("expected rewritten packet to parse")
	}

	decision := PlanOutbound(packet, parsed, state)
	if decision.Action != ActionInject {
		t.Fatalf("expected inject, got %v", decision.Action)
	}

	translated, ok := netpacket.ParseIPv4(decision.Packet)
	if !ok {
		t.Fatal("expected translated packet to parse")
	}
	if translated.SourceAddr != originalDst {
		t.Fatalf("expected source to reverse translate to %s, got %s", originalDst, translated.SourceAddr)
	}
}

func udpPacketForTest(t *testing.T) ([]byte, netpacket.IPv4Packet) {
	t.Helper()

	packet := makeForwardingUDPPacket(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("192.168.0.20"),
		12000,
		8080,
		nil,
	)
	parsed, ok := netpacket.ParseIPv4(packet)
	if !ok {
		t.Fatal("expected test packet to parse")
	}
	return packet, parsed
}

func makeForwardingUDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ipv4Header := header.IPv4(packet)
	ipv4Header.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())
	udpHeader := header.UDP(packet[header.IPv4MinimumSize:])
	udpHeader.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(packet[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		ipv4Header.SourceAddress(),
		ipv4Header.DestinationAddress(),
		uint16(header.UDPMinimumSize+len(payload)),
	)
	xsum = checksum.Checksum(packet[header.IPv4MinimumSize:], xsum)
	udpHeader.SetChecksum(^xsum)
	return packet
}
