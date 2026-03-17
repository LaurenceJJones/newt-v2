package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/fosrl/newt/internal/netstack/dnsclient"
	"github.com/fosrl/newt/internal/netstack/dialer"
	"github.com/fosrl/newt/internal/netstack/ping"
	stackproxy "github.com/fosrl/newt/internal/netstack/proxy"
	stackrules "github.com/fosrl/newt/internal/netstack/rules"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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

type device struct {
	owner          *Net
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
}

// Net owns the userspace network stack and proxy rule state.
type Net struct {
	dev          *device
	dnsServers   []netip.Addr
	hasV4, hasV6 bool
	proxyHandler *stackproxy.Handler
	proxyRules   *stackrules.Lookup
}

// CreateTUN creates a userspace TUN and the associated netstack.
func CreateTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error) {
	return CreateTUNWithOptions(localAddresses, dnsServers, mtu, Options{
		EnableTCPProxy:  true,
		EnableUDPProxy:  true,
		EnableICMPProxy: true,
	})
}

// CreateTUNWithOptions creates a userspace TUN with optional proxy handlers.
func CreateTUNWithOptions(localAddresses, dnsServers []netip.Addr, mtu int, options Options) (tun.Device, *Net, error) {
	dev := &device{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(defaultStackOptions()),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}
	n := &Net{
		dev:        dev,
		dnsServers: dnsServers,
		proxyRules: stackrules.NewLookup(),
	}
	dev.owner = n

	if err := n.initializeProxy(options); err != nil {
		return nil, nil, err
	}
	if err := n.configureTCP(); err != nil {
		return nil, nil, err
	}
	if err := n.initializeMainNIC(); err != nil {
		return nil, nil, err
	}
	if err := n.initializeProxyNIC(); err != nil {
		return nil, nil, err
	}
	if err := n.configureLocalAddresses(localAddresses); err != nil {
		return nil, nil, err
	}
	if err := n.configureForwarding(); err != nil {
		return nil, nil, err
	}
	n.configureRoutes()

	n.dev.events <- tun.EventUp
	return n.dev, n, nil
}

func defaultStackOptions() stack.Options {
	return stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
}

func (n *Net) initializeProxy(options Options) error {
	proxyHandler, err := stackproxy.NewHandlerWithFlags(
		options.EnableTCPProxy,
		options.EnableUDPProxy,
		options.EnableICMPProxy,
		n.dev.mtu,
	)
	if err != nil {
		return fmt.Errorf("failed to create proxy handler: %v", err)
	}
	n.proxyHandler = proxyHandler
	return nil
}

func (n *Net) configureTCP() error {
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if err := n.dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		return fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	return nil
}

func (n *Net) initializeMainNIC() error {
	n.dev.notifyHandle = n.dev.ep.AddNotify(n.dev)
	if err := n.dev.stack.CreateNIC(1, n.dev.ep); err != nil {
		return fmt.Errorf("CreateNIC: %v", err)
	}
	return nil
}

func (n *Net) initializeProxyNIC() error {
	if n.proxyHandler == nil {
		return nil
	}
	return n.proxyHandler.Initialize(n.dev)
}

func (n *Net) configureLocalAddresses(localAddresses []netip.Addr) error {
	for _, ip := range localAddresses {
		normalized, protoNumber, ok := protocolAddressFor(ip)
		if !ok {
			return fmt.Errorf("AddProtocolAddress(%v): unsupported address family", ip)
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(normalized.AsSlice()).WithPrefix(),
		}
		if err := n.dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("AddProtocolAddress(%v): %v", normalized, err)
		}
		if normalized.Is4() {
			n.hasV4 = true
		} else if normalized.Is6() {
			n.hasV6 = true
		}
	}
	return nil
}

func (n *Net) configureForwarding() error {
	if n.hasV4 {
		if err := n.dev.stack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
			return fmt.Errorf("set ipv4 forwarding: %s", err)
		}
	}
	if n.hasV6 {
		if err := n.dev.stack.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
			return fmt.Errorf("set ipv6 forwarding: %s", err)
		}
	}
	return nil
}

func (n *Net) configureRoutes() {
	if n.hasV4 {
		n.dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if n.hasV6 {
		n.dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
}

func protocolAddressFor(addr netip.Addr) (netip.Addr, tcpip.NetworkProtocolNumber, bool) {
	normalized := addr.Unmap()
	switch {
	case normalized.Is4():
		return normalized, ipv4.ProtocolNumber, true
	case normalized.Is6():
		return normalized, ipv6.ProtocolNumber, true
	default:
		return netip.Addr{}, 0, false
	}
}

func (d *device) Name() (string, error) { return "go", nil }
func (d *device) File() *os.File        { return nil }
func (d *device) Events() <-chan tun.Event {
	return d.events
}

func (d *device) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-d.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (d *device) Write(buf [][]byte, offset int) (int, error) {
	for _, packetBuf := range buf {
		packet := packetBuf[offset:]
		if len(packet) == 0 {
			continue
		}
		if d.handleProxyPacket(packet) {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

func (d *device) handleProxyPacket(packet []byte) bool {
	if d.owner != nil && d.owner.proxyHandler != nil {
		return d.owner.proxyHandler.HandleIncomingPacket(packet)
	}
	return false
}

func (d *device) WriteNotify() {
	pkt := d.ep.Read()
	if pkt != nil {
		view := pkt.ToView()
		pkt.DecRef()
		d.incomingPacket <- view
		return
	}
	if d.owner != nil && d.owner.proxyHandler != nil {
		if view := d.owner.proxyHandler.ReadOutgoingPacket(); view != nil {
			d.incomingPacket <- view
		}
	}
}

func (d *device) Close() error {
	d.stack.RemoveNIC(1)
	d.stack.Close()
	d.ep.RemoveNotify(d.notifyHandle)
	d.ep.Close()
	if d.owner != nil && d.owner.proxyHandler != nil {
		d.owner.proxyHandler.Close()
	}
	closeIfOpen(d.events)
	closeIfOpen(d.incomingPacket)
	return nil
}

func closeIfOpen[T any](ch chan T) {
	if ch != nil {
		close(ch)
	}
}

func (d *device) MTU() (int, error) { return d.mtu, nil }
func (d *device) BatchSize() int    { return 1 }

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

func (n *Net) LookupHost(host string) ([]string, error) {
	return n.resolver().LookupHost(host)
}

func (n *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return n.resolver().LookupContextHost(ctx, host)
}

func (n *Net) resolver() *dnsclient.Client {
	return dnsclient.New(
		n.dnsServers,
		n.hasV4,
		n.hasV6,
		func(laddr, raddr netip.AddrPort) (net.Conn, error) {
			return n.DialUDPAddrPort(laddr, raddr)
		},
		func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return n.DialContextTCPAddrPort(ctx, addr)
		},
	)
}

func (n *Net) AddProxySubnetRule(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange, disableICMP bool) {
	n.proxyRules.Add(sourcePrefix, destPrefix, rewriteTo, toRulePortRanges(portRanges), disableICMP)
	if n.proxyHandler != nil {
		n.proxyHandler.AddSubnetRule(sourcePrefix, destPrefix, rewriteTo, toRulePortRanges(portRanges), disableICMP)
	}
}

func (n *Net) RemoveProxySubnetRule(sourcePrefix, destPrefix netip.Prefix) {
	n.proxyRules.Remove(sourcePrefix, destPrefix)
	if n.proxyHandler != nil {
		n.proxyHandler.RemoveSubnetRule(sourcePrefix, destPrefix)
	}
}

func (n *Net) ProxySubnetRules() []SubnetRule {
	if n.proxyRules == nil {
		return nil
	}
	rules := n.proxyRules.All()
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
