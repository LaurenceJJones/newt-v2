package packet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// RewriteDestination rewrites the destination IPv4 address and updates checksums.
func RewriteDestination(packet []byte, newDst netip.Addr) []byte {
	return rewriteIPv4Address(packet, newDst, false)
}

// RewriteSource rewrites the source IPv4 address and updates checksums.
func RewriteSource(packet []byte, newSrc netip.Addr) []byte {
	return rewriteIPv4Address(packet, newSrc, true)
}

func rewriteIPv4Address(packet []byte, newAddr netip.Addr, rewriteSource bool) []byte {
	if len(packet) < header.IPv4MinimumSize || !newAddr.Is4() {
		return nil
	}

	pkt := append([]byte(nil), packet...)
	ipv4Header := header.IPv4(pkt)
	headerLen := int(ipv4Header.HeaderLength())

	addr := tcpip.AddrFrom4(newAddr.As4())
	if rewriteSource {
		ipv4Header.SetSourceAddress(addr)
	} else {
		ipv4Header.SetDestinationAddress(addr)
	}

	ipv4Header.SetChecksum(0)
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())

	switch ipv4Header.TransportProtocol() {
	case header.TCPProtocolNumber:
		if len(pkt) >= headerLen+header.TCPMinimumSize {
			tcpHeader := header.TCP(pkt[headerLen:])
			tcpHeader.SetChecksum(0)
			xsum := header.PseudoHeaderChecksum(
				header.TCPProtocolNumber,
				ipv4Header.SourceAddress(),
				ipv4Header.DestinationAddress(),
				uint16(len(pkt)-headerLen),
			)
			xsum = checksum.Checksum(pkt[headerLen:], xsum)
			tcpHeader.SetChecksum(^xsum)
		}
	case header.UDPProtocolNumber:
		if len(pkt) >= headerLen+header.UDPMinimumSize {
			udpHeader := header.UDP(pkt[headerLen:])
			udpHeader.SetChecksum(0)
			xsum := header.PseudoHeaderChecksum(
				header.UDPProtocolNumber,
				ipv4Header.SourceAddress(),
				ipv4Header.DestinationAddress(),
				uint16(len(pkt)-headerLen),
			)
			xsum = checksum.Checksum(pkt[headerLen:], xsum)
			udpHeader.SetChecksum(^xsum)
		}
	}

	return pkt
}
