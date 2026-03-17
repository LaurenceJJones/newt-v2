package packet

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// BuildICMPEchoReply builds an IPv4 ICMP echo-reply packet.
func BuildICMPEchoReply(srcAddr, dstAddr netip.Addr, ident, seq uint16, payload []byte) []byte {
	if !srcAddr.Is4() || !dstAddr.Is4() {
		return nil
	}

	ipHeaderLen := header.IPv4MinimumSize
	icmpHeaderLen := header.ICMPv4MinimumSize
	totalLen := ipHeaderLen + icmpHeaderLen + len(payload)
	packet := make([]byte, totalLen)

	ipHdr := header.IPv4(packet[:ipHeaderLen])
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(srcAddr.As4()),
		DstAddr:     tcpip.AddrFrom4(dstAddr.As4()),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[ipHeaderLen : ipHeaderLen+icmpHeaderLen])
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetCode(0)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetSequence(seq)
	copy(packet[ipHeaderLen+icmpHeaderLen:], payload)

	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(^checksum.Checksum(packet[ipHeaderLen:], 0))

	return packet
}
