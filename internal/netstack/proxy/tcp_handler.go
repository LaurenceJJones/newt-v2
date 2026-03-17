package proxy

import (
	"context"
	"net"

	"github.com/fosrl/newt/internal/netstack/forwarding"
	"github.com/fosrl/newt/internal/netstack/relay"
	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type TCPHandler struct {
	stack  *stack.Stack
	engine *Engine
}

func NewTCPHandler(s *stack.Stack, engine *Engine) *TCPHandler {
	return &TCPHandler{stack: s, engine: engine}
}

func (h *TCPHandler) InstallTCPHandler() error {
	tcpForwarder := tcp.NewForwarder(h.stack, defaultWndSize, maxConnAttempts, func(r *tcp.ForwarderRequest) {
		var (
			wq  waiter.Queue
			ep  tcpip.Endpoint
			err tcpip.Error
			id  = r.ID()
		)

		ep, err = r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		defer r.Complete(false)

		setTCPSocketOptions(h.stack, ep)
		netstackConn := gonet.NewTCPConn(&wq, ep)
		go h.handleTCPConn(netstackConn, id)
	})

	h.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	return nil
}

func (h *TCPHandler) handleTCPConn(netstackConn *gonet.TCPConn, id stack.TransportEndpointID) {
	defer netstackConn.Close()

	srcIP, ok := parseTransportAddress(id.RemoteAddress)
	if !ok {
		logger.Info("TCP Forwarder: Failed to parse source IP %s", id.RemoteAddress)
		return
	}
	srcPort := id.RemotePort
	dstIP, ok := parseTransportAddress(id.LocalAddress)
	if !ok {
		logger.Info("TCP Forwarder: Failed to parse destination IP %s", id.LocalAddress)
		return
	}
	dstPort := id.LocalPort

	logger.Info("TCP Forwarder: Handling connection %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)

	target := forwarding.ResolveTarget(srcIP, dstIP, dstPort, uint8(tcp.ProtocolNumber), h.engine)
	if target.Rewritten {
		logger.Info("TCP Forwarder: Using rewritten destination %s (original: %s)", target.Effective.Addr(), target.Original.Addr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "tcp", target.Effective.String())
	if err != nil {
		logger.Info("TCP Forwarder: Failed to connect to %s: %v", target.Effective, err)
		return
	}
	defer targetConn.Close()

	logger.Info("TCP Forwarder: Successfully connected to %s, starting bidirectional copy", target.Effective)
	relay.TCP(netstackConn, targetConn, relay.TCPOptions{WaitTimeout: tcpWaitTimeout})
}
