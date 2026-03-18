package clients

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/netstack"
)

func (m *Manager) addTargets(targets []control.ClientWGTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.clientNet == nil {
		return nil
	}

	for _, target := range targets {
		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			return fmt.Errorf("parse dest prefix %s: %w", target.DestPrefix, err)
		}

		portRanges := toProxyPortRanges(target.PortRange)
		for _, source := range resolveSourcePrefixes(target) {
			sourcePrefix, err := netip.ParsePrefix(source)
			if err != nil {
				return fmt.Errorf("parse source prefix %s: %w", source, err)
			}
			m.clientNet.AddForwardingRule(sourcePrefix, destPrefix, target.RewriteTo, portRanges, target.DisableIcmp)
		}
	}

	return nil
}

func (m *Manager) removeTargets(targets []control.ClientWGTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.clientNet == nil {
		return nil
	}

	for _, target := range targets {
		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			return fmt.Errorf("parse dest prefix %s: %w", target.DestPrefix, err)
		}

		for _, source := range resolveSourcePrefixes(target) {
			sourcePrefix, err := netip.ParsePrefix(source)
			if err != nil {
				return fmt.Errorf("parse source prefix %s: %w", source, err)
			}
			m.clientNet.RemoveForwardingRule(sourcePrefix, destPrefix)
		}
	}

	return nil
}

func (m *Manager) syncTargets(targets []control.ClientWGTarget) error {
	m.mu.Lock()
	if m.clientNet == nil {
		m.mu.Unlock()
		return nil
	}

	currentRules := m.clientNet.ForwardingRules()
	for _, rule := range currentRules {
		m.clientNet.RemoveForwardingRule(rule.SourcePrefix, rule.DestPrefix)
	}
	m.mu.Unlock()

	return m.addTargets(targets)
}

func resolveSourcePrefixes(target control.ClientWGTarget) []string {
	if len(target.SourcePrefixes) > 0 {
		return target.SourcePrefixes
	}
	if target.SourcePrefix != "" {
		return []string{target.SourcePrefix}
	}
	return nil
}

func toProxyPortRanges(ranges []control.ClientWGPortRange) []netstack.PortRange {
	if len(ranges) == 0 {
		return nil
	}

	out := make([]netstack.PortRange, 0, len(ranges))
	for _, pr := range ranges {
		out = append(out, netstack.PortRange{
			Min:      pr.Min,
			Max:      pr.Max,
			Protocol: pr.Protocol,
		})
	}
	return out
}
