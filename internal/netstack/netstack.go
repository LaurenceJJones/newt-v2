package netstack

import (
	"net/netip"
)

// PortRange limits a proxy rule to a protocol/port interval.
// An empty Protocol allows both TCP and UDP.
type PortRange struct {
	Min      uint16
	Max      uint16
	Protocol string
}

// SubnetRule describes one proxied subnet mapping.
type SubnetRule struct {
	SourcePrefix netip.Prefix
	DestPrefix   netip.Prefix
	DisableICMP  bool
	RewriteTo    string
	PortRanges   []PortRange
}

// Options configures userspace netstack behavior.
type Options struct {
	EnableTCPProxy  bool
	EnableUDPProxy  bool
	EnableICMPProxy bool
}
