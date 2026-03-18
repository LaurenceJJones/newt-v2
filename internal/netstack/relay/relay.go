package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const defaultBufferSize = 32 * 1024

type TCPOptions struct {
	WaitTimeout time.Duration
}

type UDPOptions struct {
	Timeout time.Duration
}

type writeCountingConn struct {
	net.Conn
	counter *atomic.Int64
	hook    func(int64)
}

func WrapWriteCounter(conn net.Conn, counter *atomic.Int64) net.Conn {
	return WrapWriteCounterWithHook(conn, counter, nil)
}

func WrapWriteCounterWithHook(conn net.Conn, counter *atomic.Int64, hook func(int64)) net.Conn {
	if conn == nil || counter == nil {
		return conn
	}
	return &writeCountingConn{Conn: conn, counter: counter, hook: hook}
}

func (c *writeCountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.counter.Add(int64(n))
	if c.hook != nil && n > 0 {
		c.hook(int64(n))
	}
	return n, err
}

func (c *writeCountingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *writeCountingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func TCP(origin, remote net.Conn, options TCPOptions) {
	var wg sync.WaitGroup
	wg.Add(2)

	go copyTCP(remote, origin, options.WaitTimeout, &wg)
	go copyTCP(origin, remote, options.WaitTimeout, &wg)

	wg.Wait()
}

func copyTCP(dst, src net.Conn, waitTimeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, defaultBufferSize)
	_, _ = io.CopyBuffer(dst, src, buf)

	if cr, ok := src.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	_ = dst.SetReadDeadline(time.Now().Add(waitTimeout))
}

func UDP(origin, remote net.PacketConn, serverAddr, clientAddr net.Addr, options UDPOptions) {
	var wg sync.WaitGroup
	wg.Add(2)

	go copyUDP(remote, origin, serverAddr, options.Timeout, &wg)
	go copyUDP(origin, remote, clientAddr, options.Timeout, &wg)

	wg.Wait()
}

func copyUDP(dst, src net.PacketConn, to net.Addr, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	_ = copyPacketData(dst, src, to, timeout)
}

func copyPacketData(dst, src net.PacketConn, to net.Addr, timeout time.Duration) error {
	buf := make([]byte, 65535)

	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, srcAddr, err := src.ReadFrom(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		writeAddr := to
		if writeAddr == nil {
			writeAddr = srcAddr
		}

		if _, err := dst.WriteTo(buf[:n], writeAddr); err != nil {
			return err
		}
		_ = dst.SetReadDeadline(time.Now().Add(timeout))
	}
}
