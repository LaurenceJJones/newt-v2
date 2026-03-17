package proxy

import (
	"net"
	"net/netip"

	"github.com/fosrl/newt/internal/netstack/forwarding"
	"github.com/fosrl/newt/internal/netstack/relay"
	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type UDPHandler struct {
	stack  *stack.Stack
	engine *Engine
}

func NewUDPHandler(s *stack.Stack, engine *Engine) *UDPHandler {
	return &UDPHandler{stack: s, engine: engine}
}

func (h *UDPHandler) InstallUDPHandler() error {
	udpForwarder := udp.NewForwarder(h.stack, func(r *udp.ForwarderRequest) {
		var (
			wq waiter.Queue
			id = r.ID()
		)

		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		netstackConn := gonet.NewUDPConn(&wq, ep)
		go h.handleUDPConn(netstackConn, id)
	})

	h.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return nil
}

func (h *UDPHandler) handleUDPConn(netstackConn *gonet.UDPConn, id stack.TransportEndpointID) {
	defer netstackConn.Close()

	srcIP, ok := parseTransportAddress(id.RemoteAddress)
	if !ok {
		logger.Info("UDP Forwarder: Failed to parse source IP %s", id.RemoteAddress)
		return
	}
	srcPort := id.RemotePort
	dstIP, ok := parseTransportAddress(id.LocalAddress)
	if !ok {
		logger.Info("UDP Forwarder: Failed to parse destination IP %s", id.LocalAddress)
		return
	}
	dstPort := id.LocalPort

	logger.Info("UDP Forwarder: Handling connection %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)

	target := forwarding.ResolveTarget(srcIP, dstIP, dstPort, uint8(udp.ProtocolNumber), h.engine)
	if target.Rewritten {
		logger.Info("UDP Forwarder: Using rewritten destination %s (original: %s)", target.Effective.Addr(), target.Original.Addr())
	}

	remoteUDPAddr := net.UDPAddrFromAddrPort(target.Effective)
	clientAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(srcIP, srcPort))
	targetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		logger.Info("UDP Forwarder: Failed to create UDP socket: %v", err)
		return
	}
	defer targetConn.Close()

	logger.Info("UDP Forwarder: Successfully created UDP socket for %s, starting bidirectional copy", target.Effective)
	relay.UDP(netstackConn, targetConn, remoteUDPAddr, clientAddr, relay.UDPOptions{Timeout: udpSessionTimeout})
}
