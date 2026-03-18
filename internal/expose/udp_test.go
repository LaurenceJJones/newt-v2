package expose

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/netstack/relay"
)

type testPacketConn struct {
	mu     sync.Mutex
	writes []packetWrite
	closed atomic.Bool
}

type packetWrite struct {
	payload []byte
	addr    net.Addr
}

func (c *testPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, timeoutError{}
}

func (c *testPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, packetWrite{
		payload: append([]byte(nil), p...),
		addr:    addr,
	})
	return len(p), nil
}

func (c *testPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *testPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *testPacketConn) writesSnapshot() []packetWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]packetWrite, len(c.writes))
	copy(out, c.writes)
	return out
}

type readResult struct {
	payload []byte
	err     error
}

type testConn struct {
	readCh     chan readResult
	writes     [][]byte
	writeErr   error
	readErr    error
	closeCount atomic.Int64
	mu         sync.Mutex
}

func newTestConn() *testConn {
	return &testConn{
		readCh: make(chan readResult, 4),
	}
}

func (c *testConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	result, ok := <-c.readCh
	if !ok {
		return 0, io.EOF
	}
	if result.err != nil {
		return 0, result.err
	}
	n := copy(p, result.payload)
	return n, nil
}

func (c *testConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *testConn) Close() error {
	c.closeCount.Add(1)
	return nil
}

func (c *testConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }
func TestUDPReadFromTargetForwardsResponsesAndUpdatesStats(t *testing.T) {
	listener := &testPacketConn{}
	targetConn := newTestConn()
	targetConn.readCh <- readResult{payload: []byte("pong")}
	close(targetConn.readCh)

	p := &UDPProxy{
		listener: listener,
		logger:   slog.Default(),
		ctx:      context.Background(),
	}
	session := &udpSession{
		clientAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 9000},
		targetConn: targetConn,
		activity:   relay.NewActivityTracker(time.Now()),
	}
	p.sessions.Store("client", session)

	p.wg.Add(1)
	p.readFromTarget(session, "client")

	writes := listener.writesSnapshot()
	if len(writes) != 1 {
		t.Fatalf("expected 1 listener write, got %d", len(writes))
	}
	if got := string(writes[0].payload); got != "pong" {
		t.Fatalf("unexpected payload: %q", got)
	}
	if got := p.bytesOut.Load(); got != 4 {
		t.Fatalf("unexpected bytesOut: %d", got)
	}
	if got := p.packetOut.Load(); got != 1 {
		t.Fatalf("unexpected packetOut: %d", got)
	}
	if got := session.bytesIn.Load(); got != 4 {
		t.Fatalf("unexpected session bytesIn: %d", got)
	}
	if _, ok := p.sessions.Load("client"); ok {
		t.Fatal("expected session to be removed after reader exit")
	}
}

func TestUDPReadFromTargetExpiresInactiveSession(t *testing.T) {
	listener := &testPacketConn{}
	targetConn := newTestConn()
	targetConn.readCh <- readResult{err: timeoutError{}}
	close(targetConn.readCh)

	p := &UDPProxy{
		listener: listener,
		logger:   slog.Default(),
		ctx:      context.Background(),
	}
	session := &udpSession{
		clientAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 9001},
		targetConn: targetConn,
		activity:   relay.NewActivityTracker(time.Now().Add(-udpSessionTimeout - time.Second)),
	}
	p.sessions.Store("client", session)

	p.wg.Add(1)
	p.readFromTarget(session, "client")

	if len(listener.writesSnapshot()) != 0 {
		t.Fatal("expected no writes for expired session")
	}
	if got := targetConn.closeCount.Load(); got == 0 {
		t.Fatal("expected target connection to be closed")
	}
	if _, ok := p.sessions.Load("client"); ok {
		t.Fatal("expected session to be removed after expiry")
	}
}

func TestUDPGetOrCreateSessionReusesExistingSession(t *testing.T) {
	existing := &udpSession{
		clientAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 30), Port: 9002},
		targetConn: newTestConn(),
		activity:   relay.NewActivityTracker(time.Now()),
	}

	p := &UDPProxy{logger: slog.Default()}
	p.sessions.Store(existing.clientAddr.String(), existing)

	got := p.getOrCreateSession(existing.clientAddr)
	if got != existing {
		t.Fatal("expected existing session to be reused")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type testNetDialer struct {
	listener net.PacketConn
}

func (d *testNetDialer) DialTCP(addr string) (net.Conn, error)         { return nil, nil }
func (d *testNetDialer) DialUDP(laddr, raddr string) (net.Conn, error) { return nil, nil }
func (d *testNetDialer) ListenTCP(addr string) (net.Listener, error)   { return nil, nil }
func (d *testNetDialer) ListenUDP(addr string) (net.PacketConn, error) { return d.listener, nil }

func TestUDPStartExitsOnContextCancel(t *testing.T) {
	listener := &testPacketConn{}
	p := NewUDPProxy(Target{ListenAddr: "127.0.0.1:1", TargetAddr: "127.0.0.1:2"}, &testNetDialer{listener: listener}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.Start(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil || err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("start did not exit after cancellation")
	}
}

func TestUDPStopClosesListenerAndSessions(t *testing.T) {
	listener := &testPacketConn{}
	sessionConn := newTestConn()

	ctx, cancel := context.WithCancel(context.Background())
	p := &UDPProxy{
		listener: listener,
		logger:   slog.Default(),
		ctx:      ctx,
		cancel:   cancel,
	}
	session := &udpSession{
		clientAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 40), Port: 9003},
		targetConn: sessionConn,
		activity:   relay.NewActivityTracker(time.Now()),
	}
	p.sessions.Store("client", session)

	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !listener.closed.Load() {
		t.Fatal("expected listener to be closed")
	}
	if got := sessionConn.closeCount.Load(); got == 0 {
		t.Fatal("expected session connection to be closed")
	}
}
