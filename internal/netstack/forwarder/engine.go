package forwarder

import (
	"bytes"
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/fosrl/newt/internal/netstack/forwarding"
	netpacket "github.com/fosrl/newt/internal/netstack/packet"
	"github.com/fosrl/newt/internal/netstack/rewrite"
	stackrules "github.com/fosrl/newt/internal/netstack/rules"
	pkglogger "github.com/fosrl/newt/pkg/logger"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Engine struct {
	proxyStack      *stack.Stack
	proxyEp         *channel.Endpoint
	subnetLookup    *stackrules.Lookup
	rewriteState    *rewrite.State
	rewriteResolver *rewrite.Resolver
	enabled         bool
	icmpReplies     chan []byte
	notifiable      channel.Notification
	closed          atomic.Bool
}

func NewEngine(proxyStack *stack.Stack, proxyEp *channel.Endpoint) *Engine {
	return &Engine{
		proxyStack:      proxyStack,
		proxyEp:         proxyEp,
		subnetLookup:    stackrules.NewLookup(),
		rewriteState:    rewrite.NewState(),
		rewriteResolver: rewrite.NewResolver(),
		enabled:         true,
		icmpReplies:     make(chan []byte, 256),
	}
}

func (e *Engine) AddSubnetRule(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []stackrules.PortRange, disableICMP bool) {
	if e == nil || !e.enabled {
		return
	}
	e.subnetLookup.Add(sourcePrefix, destPrefix, rewriteTo, portRanges, disableICMP)
}

func (e *Engine) RemoveSubnetRule(sourcePrefix, destPrefix netip.Prefix) {
	if e == nil || !e.enabled {
		return
	}
	e.subnetLookup.Remove(sourcePrefix, destPrefix)
}

func (e *Engine) GetAllRules() []stackrules.SubnetRule {
	if e == nil || !e.enabled {
		return nil
	}
	return e.subnetLookup.All()
}

func (e *Engine) LookupDestinationRewrite(srcIP, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool) {
	if e == nil || !e.enabled {
		return netip.Addr{}, false
	}
	return e.rewriteState.DestinationRewrite(srcIP, dstIP, dstPort, proto)
}

func (e *Engine) RuleLookup() *stackrules.Lookup {
	return e.subnetLookup
}

func (e *Engine) RewriteResolver() *rewrite.Resolver {
	return e.rewriteResolver
}

func (e *Engine) SetNotification(notifiable channel.Notification) {
	if e == nil || !e.enabled {
		return
	}
	e.notifiable = notifiable
}

func (e *Engine) HandleIncomingPacket(packet []byte) bool {
	if e == nil || !e.enabled {
		return false
	}
	if e.closed.Load() {
		return false
	}

	parsed, ok := netpacket.ParseIPv4(packet)
	if !ok {
		return false
	}

	srcAddr := parsed.SourceAddr
	dstAddr := parsed.DestinationAddr
	dstPort := parsed.DestinationPort
	protocol := parsed.Protocol
	if protocol == header.ICMPv4ProtocolNumber {
		pkglogger.Debug("HandleIncomingPacket: ICMP packet from %s to %s", srcAddr, dstAddr)
	} else if dstPort == 0 && protocol != header.TCPProtocolNumber && protocol != header.UDPProtocolNumber {
		pkglogger.Debug("HandleIncomingPacket: Unknown protocol %d from %s to %s", protocol, srcAddr, dstAddr)
	}

	decision, err := forwarding.PlanInbound(context.Background(), packet, parsed, e.subnetLookup, e.rewriteState, e.rewriteResolver)
	if err != nil {
		pkglogger.Debug("HandleIncomingPacket: forwarding plan failed: %v", err)
		return false
	}
	if decision.Action != forwarding.ActionInject {
		return false
	}

	if decision.Rule != nil {
		pkglogger.Debug("HandleIncomingPacket: Matched rule for %s -> %s (proto=%d, port=%d)",
			srcAddr, dstAddr, protocol, dstPort)
		if decision.Rule.RewriteTo != "" {
			if rewritten, ok := e.rewriteState.DestinationRewrite(srcAddr.String(), dstAddr.String(), dstPort, uint8(protocol)); ok && rewritten.IsLoopback() {
				pkglogger.Debug("Target is loopback, not rewriting packet - handlers will use rewrite table")
			}
		}
	}

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(decision.Packet),
	})
	e.proxyEp.InjectInbound(header.IPv4ProtocolNumber, pkb)
	pkglogger.Debug("HandleIncomingPacket: Injected packet into proxy stack (proto=%d)", protocol)
	return true
}

func (e *Engine) ReadOutgoingPacket() *buffer.View {
	if e == nil || !e.enabled {
		return nil
	}
	if e.closed.Load() {
		return nil
	}

	select {
	case icmpReply := <-e.icmpReplies:
		pkglogger.Debug("ReadOutgoingPacket: Returning ICMP reply packet (%d bytes)", len(icmpReply))
		return buffer.NewViewWithData(icmpReply)
	default:
	}

	pkt := e.proxyEp.Read()
	if pkt == nil {
		return nil
	}

	view := pkt.ToView()
	pkt.DecRef()

	packet := view.AsSlice()
	parsed, ok := netpacket.ParseIPv4(packet)
	if !ok {
		return view
	}
	if parsed.Protocol == header.ICMPv4ProtocolNumber {
		pkglogger.Debug("ReadOutgoingPacket: ICMP packet from %s to %s", parsed.SourceAddr, parsed.DestinationAddr)
		return view
	}

	decision := forwarding.PlanOutbound(packet, parsed, e.rewriteState)
	if decision.Action == forwarding.ActionDrop {
		return nil
	}
	if !bytes.Equal(decision.Packet, packet) {
		return buffer.NewViewWithData(decision.Packet)
	}
	return view
}

func (e *Engine) QueueICMPReply(packet []byte) bool {
	if e == nil || !e.enabled {
		return false
	}
	if e.closed.Load() {
		return false
	}

	select {
	case e.icmpReplies <- packet:
		pkglogger.Debug("QueueICMPReply: Queued ICMP reply packet (%d bytes)", len(packet))
		if e.notifiable != nil {
			e.notifiable.WriteNotify()
		}
		return true
	default:
		pkglogger.Warn("QueueICMPReply: ICMP reply channel full, dropping packet")
		return false
	}
}

func (e *Engine) Close() error {
	if e == nil || !e.enabled {
		return nil
	}
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	if e.proxyStack != nil {
		e.proxyStack.RemoveNIC(1)
		e.proxyStack.Close()
	}
	if e.proxyEp != nil {
		e.proxyEp.Close()
	}
	return nil
}
