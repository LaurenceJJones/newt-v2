package wgtester

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	magicHeader        uint32 = 0xDEADBEEF
	packetTypeRequest  uint8  = 1
	packetTypeResponse uint8  = 2
	packetSize                = 13
)

type packetListener interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
}

type Server struct {
	logger  *slog.Logger
	conn    packetListener
	port    uint16

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
}

func New(conn net.PacketConn, port uint16, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		logger: logger,
		conn:   conn,
		port:   port + 1,
		stopCh: make(chan struct{}),
	}
}

func (s *Server) Name() string {
	return "wgtester"
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	s.running = true
	go s.loop()
	s.logger.Debug("wgtester started", "port", s.port)
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopCh)
	_ = s.conn.Close()
	s.running = false
}

func (s *Server) loop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if err := s.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			continue
		}
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
			}
			if err == io.EOF {
				return
			}
			s.logger.Debug("wgtester read failed", "error", err)
			continue
		}
		if n < packetSize {
			continue
		}
		if binary.BigEndian.Uint32(buf[:4]) != magicHeader || buf[4] != packetTypeRequest {
			continue
		}
		s.logger.Debug("wgtester probe received", "from", addr.String(), "listen_port", s.port)

		resp := make([]byte, packetSize)
		binary.BigEndian.PutUint32(resp[:4], magicHeader)
		resp[4] = packetTypeResponse
		copy(resp[5:], buf[5:13])

		if _, err := s.conn.WriteTo(resp, normalizeAddr(addr)); err != nil {
			s.logger.Debug("wgtester write failed", "error", err)
		} else {
			s.logger.Debug("wgtester probe responded", "to", addr.String(), "listen_port", s.port)
		}
	}
}

func normalizeAddr(addr net.Addr) net.Addr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return addr
	}
	addrPort := udpAddr.AddrPort()
	if addrPort.Addr().Is4In6() {
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
	}
	return net.UDPAddrFromAddrPort(addrPort)
}
