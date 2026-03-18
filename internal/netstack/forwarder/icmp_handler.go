package forwarder

import (
	"context"
	"net/netip"

	"github.com/fosrl/newt/internal/netstack/forwarding"
	"github.com/fosrl/newt/internal/netstack/icmpprobe"
	netpacket "github.com/fosrl/newt/internal/netstack/packet"
	pkglogger "github.com/fosrl/newt/pkg/logger"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ICMPHandler struct {
	stack  *stack.Stack
	engine *Engine
	prober *icmpprobe.Prober
}

func NewICMPHandler(s *stack.Stack, engine *Engine) *ICMPHandler {
	return &ICMPHandler{stack: s, engine: engine, prober: icmpprobe.New(icmpTimeout)}
}

func (h *ICMPHandler) InstallICMPHandler() error {
	h.stack.SetTransportProtocolHandler(header.ICMPv4ProtocolNumber, h.handleICMPPacket)
	pkglogger.Debug("ICMP Handler: Installed ICMP protocol handler")
	return nil
}

func (h *ICMPHandler) handleICMPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	pkglogger.Debug("ICMP Handler: Received ICMP packet from %s to %s", id.RemoteAddress, id.LocalAddress)

	icmpData := pkt.TransportHeader().Slice()
	if len(icmpData) < header.ICMPv4MinimumSize {
		pkglogger.Debug("ICMP Handler: Packet too small for ICMP header: %d bytes", len(icmpData))
		return false
	}

	icmpHdr := header.ICMPv4(icmpData)
	if icmpHdr.Type() != header.ICMPv4Echo {
		pkglogger.Debug("ICMP Handler: Ignoring non-echo ICMP type: %d", icmpHdr.Type())
		return false
	}

	srcIP := id.RemoteAddress.String()
	dstIP := id.LocalAddress.String()
	pkglogger.Debug("ICMP Handler: Echo Request from %s to %s (ident=%d, seq=%d)", srcIP, dstIP, icmpHdr.Ident(), icmpHdr.Sequence())

	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		pkglogger.Debug("ICMP Handler: Failed to parse source IP %s: %v", srcIP, err)
		return false
	}
	dstAddr, err := netip.ParseAddr(dstIP)
	if err != nil {
		pkglogger.Debug("ICMP Handler: Failed to parse dest IP %s: %v", dstIP, err)
		return false
	}

	decision, err := forwarding.PlanICMP(context.Background(), srcAddr, dstAddr, h.engine.RuleLookup(), h.engine.RewriteResolver())
	if err != nil {
		pkglogger.Debug("ICMP Handler: planning failed: %v", err)
		return false
	}
	if decision.Action != forwarding.ICMPActionProxy {
		pkglogger.Debug("ICMP Handler: No matching subnet rule for %s -> %s", srcIP, dstIP)
		return false
	}

	pkglogger.Debug("ICMP Handler: Matched subnet rule for %s -> %s", srcIP, dstIP)
	if decision.Rewritten {
		pkglogger.Debug("ICMP Handler: Using rewritten destination %s (original: %s)", decision.Effective, decision.Original)
	}

	icmpPayload := pkt.Data().AsRange().ToSlice()
	go h.proxyPing(srcIP, decision.Original.String(), decision.Effective.String(), icmpHdr.Ident(), icmpHdr.Sequence(), icmpPayload)
	return true
}

func (h *ICMPHandler) proxyPing(srcIP, originalDstIP, actualDstIP string, ident, seq uint16, payload []byte) {
	pkglogger.Debug("ICMP Handler: Proxying ping from %s to %s (actual: %s), ident=%d, seq=%d", srcIP, originalDstIP, actualDstIP, ident, seq)

	method, success := h.prober.Probe(actualDstIP, ident, seq, payload)
	if !success {
		pkglogger.Debug("ICMP Handler: All ping methods failed for %s", actualDstIP)
		return
	}

	pkglogger.Debug("ICMP Handler: Ping successful to %s using %s, injecting reply (ident=%d, seq=%d)", actualDstIP, method, ident, seq)
	h.injectICMPReply(srcIP, originalDstIP, ident, seq, payload)
}

func (h *ICMPHandler) injectICMPReply(dstIP, srcIP string, ident, seq uint16, payload []byte) {
	pkglogger.Debug("ICMP Handler: Creating reply from %s to %s (ident=%d, seq=%d)", srcIP, dstIP, ident, seq)

	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		pkglogger.Debug("ICMP Handler: Failed to parse source IP for reply: %v", err)
		return
	}
	dstAddr, err := netip.ParseAddr(dstIP)
	if err != nil {
		pkglogger.Debug("ICMP Handler: Failed to parse dest IP for reply: %v", err)
		return
	}

	pkt := netpacket.BuildICMPEchoReply(srcAddr, dstAddr, ident, seq, payload)
	if pkt == nil {
		pkglogger.Warn("ICMP Handler: Failed to build echo reply packet")
		return
	}
	pkglogger.Debug("ICMP Handler: Built reply packet, total length=%d", len(pkt))

	if h.engine.QueueICMPReply(pkt) {
		pkglogger.Debug("ICMP Handler: Queued echo reply packet for transmission")
	} else {
		pkglogger.Debug("ICMP Handler: Failed to queue echo reply packet")
	}
}
