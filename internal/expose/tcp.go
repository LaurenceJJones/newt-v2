package expose

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/internal/netstack/relay"
	"github.com/fosrl/newt/internal/telemetry"
)

// TCPProxy handles TCP proxying for a single target.
type TCPProxy struct {
	target   Target
	dialer   NetDialer
	listener net.Listener
	logger   *slog.Logger

	// Statistics
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
	connCount  atomic.Int64
	errorCount atomic.Int64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTCPProxy creates a new TCP proxy for the given target.
func NewTCPProxy(target Target, dialer NetDialer, logger *slog.Logger) *TCPProxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &TCPProxy{
		target: target,
		dialer: dialer,
		logger: logger,
	}
}

// Start begins accepting connections and proxying them.
func (p *TCPProxy) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Create listener
	listener, err := p.dialer.ListenTCP(p.target.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.target.ListenAddr, err)
	}
	p.listener = listener

	p.logger.Info("tcp proxy started",
		"listen", p.target.ListenAddr,
		"target", p.target.TargetAddr,
	)

	// Accept loop
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		// Set accept deadline to allow checking context
		if dl, ok := listener.(interface{ SetDeadline(time.Time) error }); ok {
			_ = dl.SetDeadline(time.Now().Add(time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			// Check if it's a timeout (expected when using deadline)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			p.logger.Warn("accept error", "error", err)
			p.errorCount.Add(1)
			telemetry.RecordProxyError(p.target.Protocol, "accept")
			continue
		}

		p.connCount.Add(1)
		telemetry.RecordProxyConnection(p.target.Protocol, p.target.TargetAddr)
		p.wg.Add(1)
		go p.handleConnection(conn)
	}
}

// handleConnection proxies a single TCP connection.
func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer func() { _ = clientConn.Close() }()

	// Connect to target via regular network (not through tunnel)
	// Targets are local services like localhost:8080
	targetConn, err := net.Dial("tcp", p.target.TargetAddr)
	if err != nil {
		p.logger.Warn("dial target failed",
			"target", p.target.TargetAddr,
			"error", err,
		)
		p.errorCount.Add(1)
		telemetry.RecordProxyError(p.target.Protocol, "dial")
		return
	}
	defer func() { _ = targetConn.Close() }()

	relay.TCP(
		relay.WrapWriteCounterWithHook(clientConn, &p.bytesIn, func(n int64) {
			telemetry.AddProxyBytes(p.target.Protocol, p.target.TargetAddr, n, 0)
		}),
		relay.WrapWriteCounterWithHook(targetConn, &p.bytesOut, func(n int64) {
			telemetry.AddProxyBytes(p.target.Protocol, p.target.TargetAddr, 0, n)
		}),
		relay.TCPOptions{WaitTimeout: 60 * time.Second},
	)
}

// Stop stops the proxy and waits for all connections to close.
func (p *TCPProxy) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}

	// Wait for connections with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.logger.Warn("timeout waiting for connections to close")
	}

	return nil
}

// Stats returns current proxy statistics.
func (p *TCPProxy) Stats() ProxyStats {
	return ProxyStats{
		BytesIn:         p.bytesIn.Load(),
		BytesOut:        p.bytesOut.Load(),
		ConnectionCount: p.connCount.Load(),
		ErrorCount:      p.errorCount.Load(),
	}
}
