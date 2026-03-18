package relay

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPRelaysBidirectionally(t *testing.T) {
	originLocal, originRemote := net.Pipe()
	targetLocal, targetRemote := net.Pipe()
	defer func() { _ = originLocal.Close() }()
	defer func() { _ = originRemote.Close() }()
	defer func() { _ = targetLocal.Close() }()
	defer func() { _ = targetRemote.Close() }()

	done := make(chan struct{})
	go func() {
		TCP(originLocal, targetLocal, TCPOptions{WaitTimeout: 10 * time.Millisecond})
		close(done)
	}()

	serverReceived := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := targetRemote.Read(buf)
		if err != nil {
			serverReceived <- nil
			return
		}
		serverReceived <- append([]byte(nil), buf[:n]...)
	}()

	if _, err := originRemote.Write([]byte("ping")); err != nil {
		t.Fatalf("write origin: %v", err)
	}
	if got := <-serverReceived; string(got) != "ping" {
		t.Fatalf("unexpected server payload: %q", got)
	}

	clientReceived := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := originRemote.Read(buf)
		if err != nil {
			clientReceived <- nil
			return
		}
		clientReceived <- append([]byte(nil), buf[:n]...)
	}()

	if _, err := targetRemote.Write([]byte("pong")); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if got := <-clientReceived; string(got) != "pong" {
		t.Fatalf("unexpected client payload: %q", got)
	}

	_ = originRemote.Close()
	_ = targetRemote.Close()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("relay did not exit")
	}
}

func TestUDPCopyPacketDataUsesSourceAddressWhenDestinationIsNil(t *testing.T) {
	src := newStubPacketConn()
	dst := newStubPacketConn()

	src.reads = []packetRead{{
		payload: []byte("hello"),
		addr:    &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9000},
	}, {
		err: timeoutError{},
	}}

	if err := copyPacketData(dst, src, nil, time.Millisecond); err != nil {
		t.Fatalf("copy packet data: %v", err)
	}

	if len(dst.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(dst.writes))
	}
	if string(dst.writes[0].payload) != "hello" {
		t.Fatalf("unexpected payload: %q", dst.writes[0].payload)
	}
	if dst.writes[0].addr.String() != "192.0.2.1:9000" {
		t.Fatalf("unexpected destination: %v", dst.writes[0].addr)
	}
}

type packetRead struct {
	payload []byte
	addr    net.Addr
	err     error
}

type packetWrite struct {
	payload []byte
	addr    net.Addr
}

type stubPacketConn struct {
	reads  []packetRead
	writes []packetWrite
	index  int
}

func newStubPacketConn() *stubPacketConn {
	return &stubPacketConn{}
}

func (c *stubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.index >= len(c.reads) {
		return 0, nil, io.EOF
	}
	read := c.reads[c.index]
	c.index++
	if read.err != nil {
		return 0, nil, read.err
	}
	n := copy(p, read.payload)
	return n, read.addr, nil
}

func (c *stubPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes = append(c.writes, packetWrite{
		payload: append([]byte(nil), p...),
		addr:    addr,
	})
	return len(p), nil
}

func (c *stubPacketConn) Close() error                     { return nil }
func (c *stubPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
