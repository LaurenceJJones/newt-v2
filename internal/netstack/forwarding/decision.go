package forwarding

import (
	"context"
	"net/netip"

	netpacket "github.com/fosrl/newt/internal/netstack/packet"
	"github.com/fosrl/newt/internal/netstack/rewrite"
	"github.com/fosrl/newt/internal/netstack/rules"
)

type Action int

const (
	ActionDrop Action = iota
	ActionInject
)

type Resolver interface {
	Resolve(ctx context.Context, rewriteTo string) (netip.Addr, error)
}

type RewriteState interface {
	ExistingConnectionRewrite(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool)
	RememberConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8, originalDst, rewrittenTo netip.Addr)
	ReverseTranslation(rewrittenSrcIP, originalSrcIP string, originalSrcPort, originalDstPort uint16, proto uint8) (netip.Addr, bool)
}

type Decision struct {
	Action Action
	Packet []byte
	Rule   *rules.SubnetRule
}

func PlanInbound(ctx context.Context, packet []byte, parsed netpacket.IPv4Packet, lookup *rules.Lookup, state RewriteState, resolver Resolver) (Decision, error) {
	rule := lookup.Match(parsed.SourceAddr, parsed.DestinationAddr, parsed.DestinationPort, parsed.Protocol)
	if rule == nil {
		return Decision{Action: ActionDrop}, nil
	}

	decision := Decision{
		Action: ActionInject,
		Packet: packet,
		Rule:   rule,
	}

	if rule.RewriteTo == "" {
		return decision, nil
	}

	newDst, ok := state.ExistingConnectionRewrite(
		parsed.SourceAddr.String(),
		parsed.SourcePort,
		parsed.DestinationAddr.String(),
		parsed.DestinationPort,
		uint8(parsed.Protocol),
	)
	if !ok {
		var err error
		newDst, err = resolver.Resolve(ctx, rule.RewriteTo)
		if err != nil {
			return decision, nil
		}
		state.RememberConnection(
			parsed.SourceAddr.String(),
			parsed.SourcePort,
			parsed.DestinationAddr.String(),
			parsed.DestinationPort,
			uint8(parsed.Protocol),
			parsed.DestinationAddr,
			newDst,
		)
	}

	if newDst.IsLoopback() {
		return decision, nil
	}

	rewritten := netpacket.RewriteDestination(packet, newDst)
	if rewritten == nil {
		return Decision{Action: ActionDrop}, nil
	}
	decision.Packet = rewritten
	return decision, nil
}

func PlanOutbound(packet []byte, parsed netpacket.IPv4Packet, state RewriteState) Decision {
	if parsed.Protocol == 0 {
		return Decision{Action: ActionInject, Packet: packet}
	}
	if originalDst, ok := state.ReverseTranslation(
		parsed.SourceAddr.String(),
		parsed.DestinationAddr.String(),
		parsed.DestinationPort,
		parsed.SourcePort,
		uint8(parsed.Protocol),
	); ok {
		rewritten := netpacket.RewriteSource(packet, originalDst)
		if rewritten == nil {
			return Decision{Action: ActionDrop}
		}
		return Decision{Action: ActionInject, Packet: rewritten}
	}
	return Decision{Action: ActionInject, Packet: packet}
}

var _ RewriteState = (*rewrite.State)(nil)
