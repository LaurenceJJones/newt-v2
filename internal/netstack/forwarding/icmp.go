package forwarding

import (
	"context"
	"net/netip"

	"github.com/fosrl/newt/internal/netstack/rules"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type ICMPAction int

const (
	ICMPActionDrop ICMPAction = iota
	ICMPActionProxy
)

type ICMPDecision struct {
	Action    ICMPAction
	Rule      *rules.SubnetRule
	Original  netip.Addr
	Effective netip.Addr
	Rewritten bool
}

func PlanICMP(ctx context.Context, srcAddr, dstAddr netip.Addr, lookup *rules.Lookup, resolver Resolver) (ICMPDecision, error) {
	if lookup == nil {
		return ICMPDecision{Action: ICMPActionDrop}, nil
	}

	rule := lookup.Match(srcAddr, dstAddr, 0, header.ICMPv4ProtocolNumber)
	if rule == nil {
		return ICMPDecision{Action: ICMPActionDrop}, nil
	}

	decision := ICMPDecision{
		Action:    ICMPActionProxy,
		Rule:      rule,
		Original:  dstAddr,
		Effective: dstAddr,
	}

	if rule.RewriteTo == "" {
		return decision, nil
	}

	rewritten, err := resolver.Resolve(ctx, rule.RewriteTo)
	if err != nil {
		return decision, nil
	}

	decision.Effective = rewritten
	decision.Rewritten = true
	return decision, nil
}
