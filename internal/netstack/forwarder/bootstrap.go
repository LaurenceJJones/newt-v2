package forwarder

import (
	"fmt"

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

func newStackAndEndpoint(mtu int) (*stack.Stack, *channel.Endpoint) {
	proxyEp := channel.New(1024, uint32(mtu), "")
	proxyStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	return proxyStack, proxyEp
}

func initializeNIC(proxyStack *stack.Stack, proxyEp *channel.Endpoint, notifiable channel.Notification) (*channel.NotificationHandle, error) {
	handle := proxyEp.AddNotify(notifiable)
	if err := proxyStack.CreateNICWithOptions(1, proxyEp, stack.NICOptions{}); err != nil {
		proxyEp.RemoveNotify(handle)
		return nil, fmt.Errorf("CreateNIC (proxy): %v", err)
	}
	if err := proxyStack.SetPromiscuousMode(1, true); err != nil {
		proxyEp.RemoveNotify(handle)
		return nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}
	if err := proxyStack.SetSpoofing(1, true); err != nil {
		proxyEp.RemoveNotify(handle)
		return nil, fmt.Errorf("SetSpoofing: %v", err)
	}
	addDefaultRoutes(proxyStack)
	return handle, nil
}

func addDefaultRoutes(proxyStack *stack.Stack) {
	proxyStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	})
	proxyStack.AddRoute(tcpip.Route{
		Destination: header.IPv6EmptySubnet,
		NIC:         1,
	})
}
