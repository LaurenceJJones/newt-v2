package netstack

import (
	"net/netip"

	stackrules "github.com/fosrl/newt/internal/netstack/rules"
)

func (n *Net) AddForwardingRule(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange, disableICMP bool) {
	n.subnetRules.Add(sourcePrefix, destPrefix, rewriteTo, toRulePortRanges(portRanges), disableICMP)
	if n.forwarder != nil {
		n.forwarder.AddSubnetRule(sourcePrefix, destPrefix, rewriteTo, toRulePortRanges(portRanges), disableICMP)
	}
}

func (n *Net) RemoveForwardingRule(sourcePrefix, destPrefix netip.Prefix) {
	n.subnetRules.Remove(sourcePrefix, destPrefix)
	if n.forwarder != nil {
		n.forwarder.RemoveSubnetRule(sourcePrefix, destPrefix)
	}
}

func (n *Net) ForwardingRules() []SubnetRule {
	if n.subnetRules == nil {
		return nil
	}
	rules := n.subnetRules.All()
	out := make([]SubnetRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, SubnetRule{
			SourcePrefix: rule.SourcePrefix,
			DestPrefix:   rule.DestPrefix,
			DisableICMP:  rule.DisableIcmp,
			RewriteTo:    rule.RewriteTo,
			PortRanges:   fromRulePortRanges(rule.PortRanges),
		})
	}
	return out
}

func (n *Net) Close() error {
	return nil
}

func toRulePortRanges(ranges []PortRange) []stackrules.PortRange {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]stackrules.PortRange, 0, len(ranges))
	for _, pr := range ranges {
		out = append(out, stackrules.PortRange{
			Min:      pr.Min,
			Max:      pr.Max,
			Protocol: pr.Protocol,
		})
	}
	return out
}

func fromRulePortRanges(ranges []stackrules.PortRange) []PortRange {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]PortRange, 0, len(ranges))
	for _, pr := range ranges {
		out = append(out, PortRange{
			Min:      pr.Min,
			Max:      pr.Max,
			Protocol: pr.Protocol,
		})
	}
	return out
}
