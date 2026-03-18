// Package proxy provides TCP and UDP proxying through the WireGuard tunnel.
package proxy

import (
	"net"
)

// Target represents a proxy target configuration.
type Target struct {
	// ID is the unique identifier for this target
	ID int

	// Protocol is "tcp" or "udp"
	Protocol string

	// ListenAddr is the address to listen on (e.g., "10.0.0.1:8080")
	ListenAddr string

	// TargetAddr is the address to forward to (e.g., "192.168.1.1:80")
	TargetAddr string

	// Enabled indicates whether the target is active
	Enabled bool
}

// TargetKey uniquely identifies a proxy target.
type TargetKey struct {
	Protocol   string
	ListenAddr string
}

// NetDialer is an interface for creating network connections.
// This allows us to dial through the tunnel's netstack.
type NetDialer interface {
	// DialTCP creates a TCP connection to the given address.
	DialTCP(addr string) (net.Conn, error)

	// DialUDP creates a UDP connection to the given address.
	DialUDP(laddr, raddr string) (net.Conn, error)

	// ListenTCP creates a TCP listener on the given address.
	ListenTCP(addr string) (net.Listener, error)

	// ListenUDP creates a UDP listener on the given address.
	ListenUDP(addr string) (net.PacketConn, error)
}

// ProxyStats contains statistics for a proxy target.
type ProxyStats struct {
	BytesIn         int64
	BytesOut        int64
	ConnectionCount int64
	ErrorCount      int64
}
