package proxy

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
)

const (
	// udpBufferSize is the size of the UDP read buffer.
	udpBufferSize = 65535

	// udpSessionTimeout is how long to keep UDP sessions alive.
	udpSessionTimeout = 60 * time.Second
)

// UDPProxy handles UDP proxying for a single target.
type UDPProxy struct {
	target   Target
	dialer   NetDialer
	listener net.PacketConn
	logger   *slog.Logger

	// Session tracking
	sessions sync.Map // map[string]*udpSession

	// Statistics
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
	packetIn   atomic.Int64
	packetOut  atomic.Int64
	errorCount atomic.Int64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// udpSession represents a UDP client session.
type udpSession struct {
	clientAddr net.Addr
	targetConn net.Conn
	activity   *relay.ActivityTracker
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

// NewUDPProxy creates a new UDP proxy for the given target.
func NewUDPProxy(target Target, dialer NetDialer, logger *slog.Logger) *UDPProxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &UDPProxy{
		target: target,
		dialer: dialer,
		logger: logger,
	}
}

// Start begins accepting packets and proxying them.
func (p *UDPProxy) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Create listener
	listener, err := p.dialer.ListenUDP(p.target.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.target.ListenAddr, err)
	}
	p.listener = listener

	p.logger.Info("udp proxy started",
		"listen", p.target.ListenAddr,
		"target", p.target.TargetAddr,
	)

	// Start session cleanup goroutine
	p.wg.Add(1)
	go p.cleanupSessions()

	// Read loop
	buf := make([]byte, udpBufferSize)
	for {
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		// Set read deadline to allow checking context
		if err := p.listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			p.logger.Warn("set deadline error", "error", err)
		}

		n, clientAddr, err := p.listener.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			p.logger.Warn("read error", "error", err)
			p.errorCount.Add(1)
			continue
		}

		p.packetIn.Add(1)
		p.bytesIn.Add(int64(n))

		// Get or create session
		session := p.getOrCreateSession(clientAddr)
		if session == nil {
			continue
		}

		// Forward to target
		session.activity.Touch(time.Now())
		_, err = session.targetConn.Write(buf[:n])
		if err != nil {
			p.logger.Debug("write to target error", "error", err)
			p.errorCount.Add(1)
			continue
		}
		session.bytesOut.Add(int64(n))
	}
}

// getOrCreateSession returns an existing session or creates a new one.
func (p *UDPProxy) getOrCreateSession(clientAddr net.Addr) *udpSession {
	key := clientAddr.String()

	// Check for existing session
	if val, ok := p.sessions.Load(key); ok {
		return val.(*udpSession)
	}

	// Create new session - dial via regular network (not through tunnel)
	// Targets are local services
	targetConn, err := net.Dial("udp", p.target.TargetAddr)
	if err != nil {
		p.logger.Warn("dial target failed", "target", p.target.TargetAddr, "error", err)
		p.errorCount.Add(1)
		return nil
	}

	session := &udpSession{
		clientAddr: clientAddr,
		targetConn: targetConn,
		activity:   relay.NewActivityTracker(time.Now()),
	}

	// Store session
	actual, loaded := p.sessions.LoadOrStore(key, session)
	if loaded {
		// Another goroutine created the session first
		targetConn.Close()
		return actual.(*udpSession)
	}

	// Start reader goroutine for responses
	p.wg.Add(1)
	go p.readFromTarget(session, key)

	return session
}

// readFromTarget reads responses from target and sends to client.
func (p *UDPProxy) readFromTarget(session *udpSession, key string) {
	defer p.wg.Done()
	defer func() {
		session.targetConn.Close()
		p.sessions.Delete(key)
	}()

	buf := make([]byte, udpBufferSize)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// Set read deadline
		if err := session.targetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}

		n, err := session.targetConn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Check if session expired
				if session.activity.Expired(time.Now(), udpSessionTimeout) {
					p.logger.Debug("session expired", "client", session.clientAddr)
					return
				}
				continue
			}
			if !errors.Is(err, context.Canceled) {
				p.logger.Debug("read from target error", "error", err)
			}
			return
		}

		session.activity.Touch(time.Now())
		session.bytesIn.Add(int64(n))
		p.bytesOut.Add(int64(n))
		p.packetOut.Add(1)

		// Send to client
		_, err = p.listener.WriteTo(buf[:n], session.clientAddr)
		if err != nil {
			p.logger.Debug("write to client error", "error", err)
			p.errorCount.Add(1)
		}
	}
}

// cleanupSessions periodically removes expired sessions.
func (p *UDPProxy) cleanupSessions() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			p.sessions.Range(func(key, value any) bool {
				session := value.(*udpSession)
				if session.activity.Expired(now, udpSessionTimeout) {
					p.logger.Debug("cleaning up expired session", "client", session.clientAddr)
					session.targetConn.Close()
					p.sessions.Delete(key)
				}
				return true
			})
		}
	}
}

// Stop stops the proxy and waits for all sessions to close.
func (p *UDPProxy) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.listener != nil {
		p.listener.Close()
	}

	// Close all sessions
	p.sessions.Range(func(key, value any) bool {
		session := value.(*udpSession)
		session.targetConn.Close()
		return true
	})

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.logger.Warn("timeout waiting for sessions to close")
	}

	return nil
}

// Stats returns current proxy statistics.
func (p *UDPProxy) Stats() ProxyStats {
	return ProxyStats{
		BytesIn:         p.bytesIn.Load(),
		BytesOut:        p.bytesOut.Load(),
		ConnectionCount: p.packetIn.Load(),
		ErrorCount:      p.errorCount.Load(),
	}
}
