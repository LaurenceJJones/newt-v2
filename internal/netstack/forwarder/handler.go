package forwarder

import (
	"fmt"
	"net/netip"

	stackrules "github.com/fosrl/newt/internal/netstack/rules"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Handler struct {
	proxyStack        *stack.Stack
	proxyEp           *channel.Endpoint
	proxyNotifyHandle *channel.NotificationHandle
	tcpHandler        *TCPHandler
	udpHandler        *UDPHandler
	icmpHandler       *ICMPHandler
	engine            *Engine
	enabled           bool
}

func NewHandlerWithFlags(enableTCP, enableUDP, enableICMP bool, mtu int) (*Handler, error) {
	proxyStack, proxyEp := newStackAndEndpoint(mtu)
	return NewHandlerWithDeps(enableTCP, enableUDP, enableICMP, proxyStack, proxyEp)
}

func NewHandlerWithDeps(enableTCP, enableUDP, enableICMP bool, proxyStack *stack.Stack, proxyEp *channel.Endpoint) (*Handler, error) {
	if !enableTCP && !enableUDP && !enableICMP {
		return nil, nil
	}

	handler := &Handler{
		enabled:    true,
		proxyStack: proxyStack,
		proxyEp:    proxyEp,
	}
	handler.engine = NewEngine(proxyStack, proxyEp)

	if enableTCP {
		handler.tcpHandler = NewTCPHandler(handler.proxyStack, handler.engine)
		if err := handler.tcpHandler.InstallTCPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install TCP handler: %v", err)
		}
	}
	if enableUDP {
		handler.udpHandler = NewUDPHandler(handler.proxyStack, handler.engine)
		if err := handler.udpHandler.InstallUDPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install UDP handler: %v", err)
		}
	}
	if enableICMP {
		handler.icmpHandler = NewICMPHandler(handler.proxyStack, handler.engine)
		if err := handler.icmpHandler.InstallICMPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install ICMP handler: %v", err)
		}
	}

	return handler, nil
}

func (h *Handler) Initialize(notifiable channel.Notification) error {
	if h == nil || !h.enabled {
		return nil
	}

	h.engine.SetNotification(notifiable)
	handle, err := initializeNIC(h.proxyStack, h.proxyEp, notifiable)
	if err != nil {
		return err
	}
	h.proxyNotifyHandle = handle
	return nil
}

func (h *Handler) HandleIncomingPacket(packet []byte) bool {
	return h.engine.HandleIncomingPacket(packet)
}

func (h *Handler) ReadOutgoingPacket() *buffer.View {
	return h.engine.ReadOutgoingPacket()
}

func (h *Handler) Close() error {
	if h == nil || !h.enabled {
		return nil
	}
	if h.proxyEp != nil && h.proxyNotifyHandle != nil {
		h.proxyEp.RemoveNotify(h.proxyNotifyHandle)
		h.proxyNotifyHandle = nil
	}
	return h.engine.Close()
}

func (h *Handler) AddSubnetRule(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []stackrules.PortRange, disableICMP bool) {
	h.engine.AddSubnetRule(sourcePrefix, destPrefix, rewriteTo, portRanges, disableICMP)
}

func (h *Handler) RemoveSubnetRule(sourcePrefix, destPrefix netip.Prefix) {
	h.engine.RemoveSubnetRule(sourcePrefix, destPrefix)
}

func (h *Handler) GetAllRules() []stackrules.SubnetRule {
	return h.engine.GetAllRules()
}
