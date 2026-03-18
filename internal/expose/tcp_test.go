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
)

type testListener struct {
	connCh   chan net.Conn
	closed   atomic.Bool
	deadline atomic.Int64
}

func newTestListener() *testListener {
	return &testListener{
		connCh: make(chan net.Conn, 4),
	}
}

func (l *testListener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case conn, ok := <-l.connCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	default:
		return nil, timeoutError{}
	}
}

func (l *testListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.connCh)
	}
	return nil
}

func (l *testListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *testListener) SetDeadline(t time.Time) error {
	l.deadline.Store(t.UnixNano())
	return nil
}

type tcpTestDialer struct {
	listener net.Listener
}

func (d *tcpTestDialer) DialTCP(addr string) (net.Conn, error)         { return nil, nil }
func (d *tcpTestDialer) DialUDP(laddr, raddr string) (net.Conn, error) { return nil, nil }
func (d *tcpTestDialer) ListenTCP(addr string) (net.Listener, error)   { return d.listener, nil }
func (d *tcpTestDialer) ListenUDP(addr string) (net.PacketConn, error) { return nil, nil }

func TestTCPHandleConnectionUpdatesStats(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		if string(buf) != "ping" {
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	clientConn, proxyConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	p := NewTCPProxy(Target{TargetAddr: targetListener.Addr().String()}, &tcpTestDialer{}, slog.Default())
	p.ctx = context.Background()
	p.wg.Add(1)
	go p.handleConnection(proxyConn)

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write client: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: %q", reply)
	}

	_ = clientConn.Close()
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not exit")
	}

	<-serverDone

	if got := p.bytesOut.Load(); got != 4 {
		t.Fatalf("unexpected bytesOut: %d", got)
	}
	if got := p.bytesIn.Load(); got != 4 {
		t.Fatalf("unexpected bytesIn: %d", got)
	}
}

func TestTCPStartExitsOnContextCancel(t *testing.T) {
	listener := newTestListener()
	p := NewTCPProxy(Target{ListenAddr: "127.0.0.1:1", TargetAddr: "127.0.0.1:2"}, &tcpTestDialer{listener: listener}, slog.Default())

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

func TestTCPStopClosesListenerAndWaitsForConnections(t *testing.T) {
	listener := newTestListener()
	clientConn, proxyConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	p := NewTCPProxy(Target{}, &tcpTestDialer{listener: listener}, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx
	p.cancel = cancel
	p.listener = listener
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()
		<-p.ctx.Done()
		_ = proxyConn.Close()
	}()

	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !listener.closed.Load() {
		t.Fatal("expected listener to be closed")
	}
}

func TestTCPStartAcceptsConnectionsAndCountsThem(t *testing.T) {
	listener := newTestListener()
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
	}()

	p := NewTCPProxy(Target{
		ListenAddr: "127.0.0.1:1",
		TargetAddr: targetListener.Addr().String(),
	}, &tcpTestDialer{listener: listener}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.Start(ctx)
	}()

	clientConn, proxyConn := net.Pipe()
	listener.connCh <- proxyConn

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write client: %v", err)
	}
	_ = clientConn.Close()

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

	<-serverDone

	if got := p.connCount.Load(); got != 1 {
		t.Fatalf("unexpected connCount: %d", got)
	}
}

var _ net.Listener = (*testListener)(nil)
var _ NetDialer = (*tcpTestDialer)(nil)
var _ = sync.Mutex{}
