package ping

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Addr struct{ addr netip.Addr }

func AddrFrom(addr netip.Addr) *Addr {
	return &Addr{addr: addr}
}

func (ia Addr) String() string {
	return ia.addr.String()
}

func (ia Addr) Network() string {
	if ia.addr.Is4() {
		return "ping4"
	}
	if ia.addr.Is6() {
		return "ping6"
	}
	return "ping"
}

func (ia Addr) Addr() netip.Addr {
	return ia.addr
}

type Conn struct {
	laddr    Addr
	raddr    Addr
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
}

type FullAddressConverter func(netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber)

func Dial(s *stack.Stack, laddr, raddr netip.Addr, convert FullAddressConverter) (*Conn, error) {
	if !laddr.IsValid() && !raddr.IsValid() {
		return nil, errors.New("ping dial: invalid address")
	}

	v6 := laddr.Is6() || raddr.Is6()
	bind := laddr.IsValid()
	if !bind {
		if v6 {
			laddr = netip.IPv6Unspecified()
		} else {
			laddr = netip.IPv4Unspecified()
		}
	}

	tn := icmp.ProtocolNumber4
	pn := ipv4.ProtocolNumber
	if v6 {
		tn = icmp.ProtocolNumber6
		pn = ipv6.ProtocolNumber
	}

	pc := &Conn{
		laddr:    Addr{laddr},
		deadline: time.NewTimer(time.Hour << 10),
	}
	pc.deadline.Stop()

	ep, err := s.NewEndpoint(tn, pn, &pc.wq)
	if err != nil {
		return nil, fmt.Errorf("ping socket: endpoint: %s", err)
	}
	pc.ep = ep

	if bind {
		fa, _ := convert(netip.AddrPortFrom(laddr, 0))
		if err = pc.ep.Bind(fa); err != nil {
			return nil, fmt.Errorf("ping bind: %s", err)
		}
	}

	if raddr.IsValid() {
		pc.raddr = Addr{raddr}
		fa, _ := convert(netip.AddrPortFrom(raddr, 0))
		if err = pc.ep.Connect(fa); err != nil {
			return nil, fmt.Errorf("ping connect: %s", err)
		}
	}

	return pc, nil
}

func (pc *Conn) LocalAddr() net.Addr {
	return pc.laddr
}

func (pc *Conn) RemoteAddr() net.Addr {
	return pc.raddr
}

func (pc *Conn) Close() error {
	pc.deadline.Reset(0)
	pc.ep.Close()
	return nil
}

func (pc *Conn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (pc *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var na netip.Addr
	switch v := addr.(type) {
	case *Addr:
		na = v.addr
	case *net.IPAddr:
		na, _ = netip.AddrFromSlice(v.IP)
	default:
		return 0, fmt.Errorf("ping write: wrong net.Addr type")
	}
	if (!na.Is4() || !pc.laddr.addr.Is4()) && (!na.Is6() || !pc.laddr.addr.Is6()) {
		return 0, fmt.Errorf("ping write: mismatched protocols")
	}

	buf := bytes.NewReader(p)
	rfa, _ := convertAddrPort(na)
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &rfa,
	})
	if tcpipErr != nil {
		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
	}

	return int(n64), nil
}

func (pc *Conn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.raddr)
}

func (pc *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&e)
	defer pc.wq.EventUnregister(&e)

	select {
	case <-pc.deadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-notifyCh:
	}

	w := tcpip.SliceWriter(p)
	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{NeedRemoteAddr: true})
	if tcpipErr != nil {
		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
	}

	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
	return res.Count, &Addr{remoteAddr}, nil
}

func (pc *Conn) Read(p []byte) (n int, err error) {
	n, _, err = pc.ReadFrom(p)
	return n, err
}

func (pc *Conn) SetDeadline(t time.Time) error {
	return pc.SetReadDeadline(t)
}

func (pc *Conn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}

func convertAddrPort(addr netip.Addr) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	normalized := addr.Unmap()
	if normalized.Is4() {
		return tcpip.FullAddress{Addr: tcpip.AddrFromSlice(normalized.AsSlice())}, ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{Addr: tcpip.AddrFromSlice(normalized.AsSlice())}, ipv6.ProtocolNumber
}
