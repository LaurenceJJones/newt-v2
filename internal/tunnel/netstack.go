package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	newtnet "github.com/fosrl/newt/internal/netstack"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
)

// NetStack wraps a gVisor netstack for userspace networking.
type NetStack struct {
	net *newtnet.Net
	dev tun.Device

	localAddr netip.Addr
	dns       netip.Addr
	mtu       int
}

// NetStackConfig holds configuration for creating a netstack.
type NetStackConfig struct {
	// LocalAddr is the tunnel's local IP address
	LocalAddr netip.Addr

	// DNS is the DNS server to use
	DNS netip.Addr

	// MTU is the maximum transmission unit
	MTU int
}

// NewNetStack creates a new gVisor netstack TUN device.
func NewNetStack(cfg NetStackConfig) (*NetStack, error) {
	// Create the netstack TUN device
	tunDev, tnet, err := newtnet.CreateTUN(
		[]netip.Addr{cfg.LocalAddr},
		[]netip.Addr{cfg.DNS},
		cfg.MTU,
	)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %w", err)
	}

	return &NetStack{
		net:       tnet,
		dev:       tunDev,
		localAddr: cfg.LocalAddr,
		dns:       cfg.DNS,
		mtu:       cfg.MTU,
	}, nil
}

// Device returns the underlying TUN device for WireGuard.
func (n *NetStack) Device() tun.Device {
	return n.dev
}

// Net returns the userspace netstack facade for creating connections.
func (n *NetStack) Net() *newtnet.Net {
	return n.net
}

// LocalAddr returns the local tunnel address.
func (n *NetStack) LocalAddr() netip.Addr {
	return n.localAddr
}

// DialTCP creates a TCP connection through the tunnel.
func (n *NetStack) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve tcp addr: %w", err)
	}
	return n.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(
		netip.MustParseAddr(tcpAddr.IP.String()),
		uint16(tcpAddr.Port),
	))
}

// DialUDP creates a UDP connection through the tunnel.
func (n *NetStack) DialUDP(ctx context.Context, laddr, raddr string) (net.Conn, error) {
	// Parse addresses
	var localAddr *net.UDPAddr
	if laddr != "" {
		var err error
		localAddr, err = net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, fmt.Errorf("resolve local addr: %w", err)
		}
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote addr: %w", err)
	}

	return n.net.DialUDP(localAddr, remoteAddr)
}

// ListenTCP creates a TCP listener on the tunnel.
func (n *NetStack) ListenTCP(addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}
	return n.net.ListenTCPAddr(tcpAddr)
}

// ListenUDP creates a UDP listener on the tunnel.
func (n *NetStack) ListenUDP(addr string) (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}
	return n.net.ListenUDPAddr(udpAddr)
}

// Close shuts down the netstack.
func (n *NetStack) Close() error {
	// The TUN device will be closed by the WireGuard device
	return nil
}

// Ping sends an ICMP echo request and returns the round-trip time.
func (n *NetStack) Ping(ctx context.Context, dst string, timeout time.Duration) (time.Duration, error) {
	return n.reliablePing(ctx, dst, timeout, 5)
}

func (n *NetStack) pingOnce(ctx context.Context, dst string, timeout time.Duration) (time.Duration, error) {
	socket, err := n.net.Dial("ping4", dst)
	if err != nil {
		return 0, fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer socket.Close()

	if tcpConn, ok := socket.(interface{ SetReadBuffer(int) error }); ok {
		_ = tcpConn.SetReadBuffer(64 * 1024)
	}
	if tcpConn, ok := socket.(interface{ SetWriteBuffer(int) error }); ok {
		_ = tcpConn.SetWriteBuffer(64 * 1024)
	}

	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("newtping"),
	}

	icmpBytes, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &requestPing,
	}).Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := socket.SetReadDeadline(deadline); err != nil {
		return 0, fmt.Errorf("failed to set read deadline: %w", err)
	}

	start := time.Now()
	if _, err := socket.Write(icmpBytes); err != nil {
		return 0, fmt.Errorf("failed to write ICMP packet: %w", err)
	}

	readBuffer := make([]byte, 1500)
	nRead, err := socket.Read(readBuffer)
	if err != nil {
		return 0, fmt.Errorf("failed to read ICMP packet: %w", err)
	}

	replyPacket, err := icmp.ParseMessage(1, readBuffer[:nRead])
	if err != nil {
		return 0, fmt.Errorf("failed to parse ICMP packet: %w", err)
	}

	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return 0, fmt.Errorf("invalid reply type: got %T, want *icmp.Echo", replyPacket.Body)
	}

	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		return 0, fmt.Errorf(
			"invalid ping reply: got seq=%d data=%q, want seq=%d data=%q",
			replyPing.Seq,
			replyPing.Data,
			requestPing.Seq,
			requestPing.Data,
		)
	}

	return time.Since(start), nil
}

func (n *NetStack) reliablePing(ctx context.Context, dst string, baseTimeout time.Duration, maxAttempts int) (time.Duration, error) {
	var lastErr error
	var totalLatency time.Duration
	successCount := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		timeout := baseTimeout + time.Duration(attempt-1)*500*time.Millisecond
		timeout += time.Duration(rand.Intn(100)) * time.Millisecond

		latency, err := n.pingOnce(ctx, dst, timeout)
		if err != nil {
			lastErr = err
			if attempt < maxAttempts {
				backoff := time.Duration(attempt) * 50 * time.Millisecond
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				case <-time.After(backoff):
				}
			}
			continue
		}

		totalLatency += latency
		successCount++
		if successCount > 0 {
			return totalLatency / time.Duration(successCount), nil
		}
	}

	if successCount == 0 {
		return 0, fmt.Errorf("all %d ping attempts failed, last error: %v", maxAttempts, lastErr)
	}

	return totalLatency / time.Duration(successCount), nil
}
