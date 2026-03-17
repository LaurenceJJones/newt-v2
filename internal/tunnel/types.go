// Package tunnel provides WireGuard tunnel management with userspace networking.
package tunnel

import (
	"net/netip"
	"time"
)

// Config holds tunnel configuration.
type Config struct {
	// Interface name for the TUN device
	InterfaceName string

	// MTU for the tunnel
	MTU int

	// DNS server to use
	DNS string

	// Local WireGuard port (0 = random)
	LocalPort uint16

	// Whether to use native WireGuard interface
	NativeMode bool

	// PingInterval controls how often tunnel health is checked.
	PingInterval time.Duration

	// PingTimeout controls the timeout for each tunnel health check.
	PingTimeout time.Duration

	// Disable cloud failover when requesting reconnect candidates.
	NoCloud bool
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		InterfaceName: "newt",
		MTU:           1280,
		DNS:           "9.9.9.9",
		PingInterval:  30 * time.Second,
		PingTimeout:   5 * time.Second,
	}
}

// PeerConfig contains WireGuard peer configuration.
type PeerConfig struct {
	// PublicKey is the peer's WireGuard public key (base64)
	PublicKey string

	// Endpoint is the peer's address (host:port)
	Endpoint string

	// AllowedIPs are the IP ranges to route through this peer
	AllowedIPs []netip.Prefix

	// PersistentKeepalive interval in seconds (0 = disabled)
	PersistentKeepalive int
}

// TunnelState represents the current state of the tunnel.
type TunnelState int

const (
	StateDisconnected TunnelState = iota
	StateConnecting
	StateConnected
	StateReconnecting
)

func (s TunnelState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	default:
		return "unknown"
	}
}

// TunnelInfo contains information about an active tunnel.
type TunnelInfo struct {
	State        TunnelState
	LocalAddr    netip.Addr
	PeerKey      string
	PeerEndpoint string
	RelayPort    uint16
	BytesIn      uint64
	BytesOut     uint64

	// InitialTargets contains targets from the connect message
	InitialTCPTargets []string
	InitialUDPTargets []string

	// InitialHealthChecks contains health checks from the connect message
	InitialHealthChecks []HealthCheckInfo
}

// HealthCheckInfo contains health check configuration from server.
type HealthCheckInfo struct {
	TargetID          int
	Hostname          string
	Port              int
	Path              string
	Scheme            string
	Mode              string
	Method            string
	ExpectedStatus    int
	Headers           map[string]string
	Interval          int
	UnhealthyInterval int
	Timeout           int
	TLSServerName     string
	Enabled           bool
}
