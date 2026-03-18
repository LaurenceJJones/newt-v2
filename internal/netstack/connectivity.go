package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/fosrl/newt/internal/netstack/dialer"
	"github.com/fosrl/newt/internal/netstack/ping"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func (n *Net) convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address, dialer.Callbacks{
		Resolve: n.resolver(),
		DialTCP: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return n.DialContextTCPAddrPort(ctx, addr)
		},
		DialUDP: func(laddr, raddr netip.AddrPort) (net.Conn, error) {
			return n.DialUDPAddrPort(laddr, raddr)
		},
		DialPing: func(addr netip.Addr) (net.Conn, error) {
			return n.DialPingAddr(netip.Addr{}, addr)
		},
	})
}

func (n *Net) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	fa, pn := n.convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, n.dev.stack, fa, pn)
}

func (n *Net) DialUDP(laddr, raddr *net.UDPAddr) (net.Conn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
	}
	return n.dialUDPConnAddrPort(la, ra)
}

func (n *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	return n.dialUDPConnAddrPort(laddr, raddr)
}

func (n *Net) dialUDPConnAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		addr, proto := n.convertToFullAddr(laddr)
		lfa = &addr
		pn = proto
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		addr, proto := n.convertToFullAddr(raddr)
		rfa = &addr
		pn = proto
	}
	return gonet.DialUDP(n.dev.stack, lfa, rfa, pn)
}

func (n *Net) DialPingAddr(laddr, raddr netip.Addr) (net.Conn, error) {
	return ping.Dial(n.dev.stack, laddr, raddr, n.convertToFullAddr)
}

func (n *Net) ListenTCP(addr string) (net.Listener, error) {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse tcp addr %q: %w", addr, err)
	}
	return n.ListenTCPAddrPort(addrPort)
}

func (n *Net) ListenTCPAddr(addr *net.TCPAddr) (net.Listener, error) {
	if addr == nil {
		return n.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (n *Net) ListenTCPAddrPort(addr netip.AddrPort) (net.Listener, error) {
	fa, pn := n.convertToFullAddr(addr)
	return gonet.ListenTCP(n.dev.stack, fa, pn)
}

func (n *Net) ListenUDP(addr string) (net.PacketConn, error) {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse udp addr %q: %w", addr, err)
	}
	return n.ListenUDPAddrPort(addrPort)
}

func (n *Net) ListenUDPAddr(addr *net.UDPAddr) (net.PacketConn, error) {
	if addr == nil {
		return n.ListenUDPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.ListenUDPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (n *Net) ListenUDPAddrPort(addr netip.AddrPort) (net.PacketConn, error) {
	return n.dialUDPConnAddrPort(addr, netip.AddrPort{})
}
