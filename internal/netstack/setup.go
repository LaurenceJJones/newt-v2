package netstack

import (
	"fmt"
	"net/netip"

	stackforwarder "github.com/fosrl/newt/internal/netstack/forwarder"
	stackrules "github.com/fosrl/newt/internal/netstack/rules"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type device struct {
	owner          *Net
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
}

// Net owns the userspace network stack and subnet forwarding rule state.
type Net struct {
	dev          *device
	dnsServers   []netip.Addr
	hasV4, hasV6 bool
	forwarder    *stackforwarder.Handler
	subnetRules  *stackrules.Lookup
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
		dev:         dev,
		dnsServers:  dnsServers,
		subnetRules: stackrules.NewLookup(),
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
	forwarder, err := stackforwarder.NewHandlerWithFlags(
		options.EnableTCPProxy,
		options.EnableUDPProxy,
		options.EnableICMPProxy,
		n.dev.mtu,
	)
	if err != nil {
		return fmt.Errorf("failed to create packet forwarder: %v", err)
	}
	n.forwarder = forwarder
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
	if n.forwarder == nil {
		return nil
	}
	return n.forwarder.Initialize(n.dev)
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
