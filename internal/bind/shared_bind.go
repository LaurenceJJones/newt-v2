// Package bind provides a shared WireGuard UDP bind that can also relay packets
// between a physical UDP socket and a netstack-backed tunnel path.
package bind

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	wgConn "golang.zx2c4.com/wireguard/conn"
)

var (
	MagicTestRequest  = []byte("PANGOLIN_TEST_REQ")
	MagicTestResponse = []byte("PANGOLIN_TEST_RSP")
)

const (
	MagicPacketDataLen  = 8
	MagicTestRequestLen = 17 + MagicPacketDataLen
	MagicTestResponseLen = 17 + MagicPacketDataLen
)

type MagicResponseCallback func(addr netip.AddrPort, echoData []byte)

type injectedPacket struct {
	data     []byte
	endpoint wgConn.Endpoint
}

// WriteToUDP writes data to a UDP address using the shared socket.
func (b *SharedBind) WriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	if b.closed.Load() {
		return 0, net.ErrClosed
	}

	b.mu.RLock()
	conn := b.udpConn
	b.mu.RUnlock()
	if conn == nil {
		return 0, net.ErrClosed
	}

	return conn.WriteToUDP(data, addr)
}

// SharedBind wraps a single UDP socket for WireGuard and auxiliary traffic.
// It can also accept packets injected from a netstack relay and route replies
// back through the same source path.
type SharedBind struct {
	mu sync.RWMutex

	udpConn *net.UDPConn
	port    uint16

	refCount atomic.Int32
	closed   atomic.Bool

	netstackPackets   chan injectedPacket
	netstackConn      atomic.Pointer[net.PacketConn]
	netstackEndpoints sync.Map

	closeCh chan struct{}

	magicResponseCallback atomic.Pointer[func(addr netip.AddrPort, echoData []byte)]
}

// New creates a SharedBind that takes ownership of udpConn.
func New(udpConn *net.UDPConn) (*SharedBind, error) {
	if udpConn == nil {
		return nil, fmt.Errorf("udpConn cannot be nil")
	}

	sb := &SharedBind{
		udpConn:         udpConn,
		netstackPackets: make(chan injectedPacket, 1024),
		closeCh:         make(chan struct{}),
	}
	sb.refCount.Store(1)

	if addr, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		sb.port = uint16(addr.Port)
	}

	return sb, nil
}

// SetNetstackConn configures the packet connection used to send relay replies
// back through the tunnel netstack.
func (b *SharedBind) SetNetstackConn(conn net.PacketConn) {
	b.netstackConn.Store(&conn)
}

// GetNetstackConn returns the relay connection used for netstack replies, if set.
func (b *SharedBind) GetNetstackConn() net.PacketConn {
	ptr := b.netstackConn.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// ClearNetstackConn removes the relay connection and tracked netstack endpoints.
func (b *SharedBind) ClearNetstackConn() {
	b.netstackConn.Store(nil)
	b.netstackEndpoints = sync.Map{}
}

func (b *SharedBind) SetMagicResponseCallback(callback MagicResponseCallback) {
	if callback == nil {
		b.magicResponseCallback.Store(nil)
		return
	}
	fn := func(addr netip.AddrPort, echoData []byte) {
		callback(addr, echoData)
	}
	b.magicResponseCallback.Store(&fn)
}

// InjectPacket feeds a packet from the tunnel netstack into WireGuard's receive path.
func (b *SharedBind) InjectPacket(data []byte, fromAddr netip.AddrPort) error {
	if b.closed.Load() {
		return net.ErrClosed
	}

	if fromAddr.Addr().Is4In6() {
		fromAddr = netip.AddrPortFrom(fromAddr.Addr().Unmap(), fromAddr.Port())
	}

	b.netstackEndpoints.Store(fromAddr, struct{}{})

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case b.netstackPackets <- injectedPacket{
		data:     dataCopy,
		endpoint: &wgConn.StdNetEndpoint{AddrPort: fromAddr},
	}:
		return nil
	case <-b.closeCh:
		return net.ErrClosed
	default:
		return fmt.Errorf("netstack packet buffer full")
	}
}

// AddRef increments the ownership reference count.
func (b *SharedBind) AddRef() {
	b.refCount.Add(1)
}

// Release decrements the ownership reference count and closes the socket at zero.
func (b *SharedBind) Release() error {
	n := b.refCount.Add(-1)
	if n < 0 {
		b.refCount.Store(0)
		return fmt.Errorf("shared bind reference count went negative")
	}
	if n == 0 {
		return b.closeConnection()
	}
	return nil
}

func (b *SharedBind) closeConnection() error {
	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(b.closeCh)

	b.mu.Lock()
	defer b.mu.Unlock()

	var err error
	if b.udpConn != nil {
		err = b.udpConn.Close()
		b.udpConn = nil
	}
	b.netstackConn.Store(nil)
	b.netstackEndpoints = sync.Map{}
	return err
}

// GetUDPConn returns the underlying UDP socket.
func (b *SharedBind) GetUDPConn() *net.UDPConn {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.udpConn
}

// GetPort returns the bound UDP port.
func (b *SharedBind) GetPort() uint16 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.port
}

// GetRefCount returns the current reference count.
func (b *SharedBind) GetRefCount() int32 {
	return b.refCount.Load()
}

// IsClosed reports whether the bind is closed.
func (b *SharedBind) IsClosed() bool {
	return b.closed.Load()
}

// Close implements conn.Bind.
func (b *SharedBind) Close() error {
	return b.Release()
}

// Open implements conn.Bind.
func (b *SharedBind) Open(uport uint16) ([]wgConn.ReceiveFunc, uint16, error) {
	if b.closed.Load() {
		return nil, 0, net.ErrClosed
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.udpConn == nil {
		return nil, 0, net.ErrClosed
	}

	return []wgConn.ReceiveFunc{
		b.makeReceiveSocket(),
		b.makeReceiveNetstack(),
	}, b.port, nil
}

func (b *SharedBind) makeReceiveSocket() wgConn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
		if len(bufs) == 0 {
			return 0, nil
		}

		for {
			if b.closed.Load() {
				return 0, net.ErrClosed
			}

			b.mu.RLock()
			conn := b.udpConn
			b.mu.RUnlock()
			if conn == nil {
				return 0, net.ErrClosed
			}

			n, addr, err := conn.ReadFromUDP(bufs[0])
			if err != nil {
				return 0, err
			}

			if b.handleMagicPacket(bufs[0][:n], addr) {
				continue
			}

			addrPort := addr.AddrPort()
			if addrPort.Addr().Is4In6() {
				addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
			}

			sizes[0] = n
			eps[0] = &wgConn.StdNetEndpoint{AddrPort: addrPort}
			return 1, nil
		}
	}
}

func (b *SharedBind) handleMagicPacket(data []byte, addr *net.UDPAddr) bool {
	if len(data) >= MagicTestRequestLen && bytes.HasPrefix(data, MagicTestRequest) {
		echoData := data[len(MagicTestRequest) : len(MagicTestRequest)+MagicPacketDataLen]

		response := make([]byte, MagicTestResponseLen)
		copy(response, MagicTestResponse)
		copy(response[len(MagicTestResponse):], echoData)

		b.mu.RLock()
		conn := b.udpConn
		b.mu.RUnlock()
		if conn != nil {
			_, _ = conn.WriteToUDP(response, addr)
		}
		return true
	}

	if len(data) >= MagicTestResponseLen && bytes.HasPrefix(data, MagicTestResponse) {
		echoData := append([]byte(nil), data[len(MagicTestResponse):len(MagicTestResponse)+MagicPacketDataLen]...)
		callbackPtr := b.magicResponseCallback.Load()
		if callbackPtr != nil {
			addrPort := addr.AddrPort()
			if addrPort.Addr().Is4In6() {
				addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
			}
			(*callbackPtr)(addrPort, echoData)
		}
		return true
	}

	return false
}

func (b *SharedBind) makeReceiveNetstack() wgConn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
		if len(bufs) == 0 {
			return 0, nil
		}

		select {
		case <-b.closeCh:
			return 0, net.ErrClosed
		case pkt := <-b.netstackPackets:
			if len(pkt.data) > len(bufs[0]) {
				return 0, nil
			}
			copy(bufs[0], pkt.data)
			sizes[0] = len(pkt.data)
			eps[0] = pkt.endpoint
			return 1, nil
		}
	}
}

// Send implements conn.Bind and routes packets back through the netstack when
// they originated from the relay path.
func (b *SharedBind) Send(bufs [][]byte, ep wgConn.Endpoint) error {
	if b.closed.Load() {
		return net.ErrClosed
	}

	var destAddrPort netip.AddrPort
	if stdEp, ok := ep.(*wgConn.StdNetEndpoint); ok {
		destAddrPort = stdEp.AddrPort
	} else {
		return fmt.Errorf("unsupported endpoint type %T", ep)
	}

	if _, isNetstackEndpoint := b.netstackEndpoints.Load(destAddrPort); isNetstackEndpoint {
		if connPtr := b.netstackConn.Load(); connPtr != nil && *connPtr != nil {
			destAddr := net.UDPAddrFromAddrPort(destAddrPort)
			for _, buf := range bufs {
				if _, err := (*connPtr).WriteTo(buf, destAddr); err != nil {
					return err
				}
			}
			return nil
		}
	}

	b.mu.RLock()
	conn := b.udpConn
	b.mu.RUnlock()
	if conn == nil {
		return net.ErrClosed
	}

	destAddr := net.UDPAddrFromAddrPort(destAddrPort)
	for _, buf := range bufs {
		if _, err := conn.WriteToUDP(buf, destAddr); err != nil {
			return err
		}
	}
	return nil
}

// SetMark implements conn.Bind. It is currently a no-op.
func (b *SharedBind) SetMark(mark uint32) error {
	return nil
}

// BatchSize implements conn.Bind.
func (b *SharedBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return wgConn.IdealBatchSize
	}
	return 1
}

// ParseEndpoint implements conn.Bind.
func (b *SharedBind) ParseEndpoint(s string) (wgConn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wgConn.StdNetEndpoint{AddrPort: addrPort}, nil
}
