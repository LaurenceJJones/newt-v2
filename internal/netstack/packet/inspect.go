package packet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// IPv4Packet captures the fields the proxy path needs after parsing.
type IPv4Packet struct {
	SourceAddr      netip.Addr
	DestinationAddr netip.Addr
	SourcePort      uint16
	DestinationPort uint16
	Protocol        tcpip.TransportProtocolNumber
	HeaderLength    int
}

// ParseIPv4 extracts the proxy-relevant fields from an IPv4 packet.
// It returns false when the packet is not parseable enough for policy decisions.
func ParseIPv4(packet []byte) (IPv4Packet, bool) {
	if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
		return IPv4Packet{}, false
	}

	ipv4Header := header.IPv4(packet)
	headerLen := int(ipv4Header.HeaderLength())
	if headerLen < header.IPv4MinimumSize || len(packet) < headerLen {
		return IPv4Packet{}, false
	}

	parsed := IPv4Packet{
		SourceAddr:      netip.AddrFrom4(ipv4Header.SourceAddress().As4()),
		DestinationAddr: netip.AddrFrom4(ipv4Header.DestinationAddress().As4()),
		Protocol:        ipv4Header.TransportProtocol(),
		HeaderLength:    headerLen,
	}

	switch parsed.Protocol {
	case header.TCPProtocolNumber:
		if len(packet) < headerLen+header.TCPMinimumSize {
			return IPv4Packet{}, false
		}
		tcpHeader := header.TCP(packet[headerLen:])
		parsed.SourcePort = tcpHeader.SourcePort()
		parsed.DestinationPort = tcpHeader.DestinationPort()
	case header.UDPProtocolNumber:
		if len(packet) < headerLen+header.UDPMinimumSize {
			return IPv4Packet{}, false
		}
		udpHeader := header.UDP(packet[headerLen:])
		parsed.SourcePort = udpHeader.SourcePort()
		parsed.DestinationPort = udpHeader.DestinationPort()
	case header.ICMPv4ProtocolNumber:
		// ICMP has no ports; keep them at zero.
	default:
		// Unknown protocols still participate in rule matching with port 0.
	}

	return parsed, true
}
