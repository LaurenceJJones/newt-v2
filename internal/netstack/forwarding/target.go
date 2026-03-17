package forwarding

import "net/netip"

type DestinationRewriter interface {
	LookupDestinationRewrite(srcIP, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool)
}

type Target struct {
	Original  netip.AddrPort
	Effective netip.AddrPort
	Rewritten bool
}

func ResolveTarget(srcIP, dstIP netip.Addr, dstPort uint16, proto uint8, rewriter DestinationRewriter) Target {
	original := netip.AddrPortFrom(dstIP, dstPort)
	target := Target{
		Original:  original,
		Effective: original,
	}
	if rewriter == nil {
		return target
	}

	rewrittenAddr, ok := rewriter.LookupDestinationRewrite(srcIP.String(), dstIP.String(), dstPort, proto)
	if !ok {
		return target
	}

	target.Effective = netip.AddrPortFrom(rewrittenAddr, dstPort)
	target.Rewritten = true
	return target
}
