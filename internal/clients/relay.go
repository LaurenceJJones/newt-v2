package clients

import (
	"fmt"
	"net"

	"github.com/fosrl/newt/internal/tunnel"
)

// SetMainNetstack sets the main tunnel netstack used for direct relay.
func (m *Manager) SetMainNetstack(ns *tunnel.NetStack) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mainNetstack = ns
}

// StartDirectRelay listens on the main tunnel netstack and relays packets into
// the shared bind, mirroring the legacy direct UDP relay datapath.
func (m *Manager) StartDirectRelay(tunnelIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mainNetstack == nil {
		return fmt.Errorf("main tunnel netstack not set")
	}
	if m.sharedBind == nil {
		return fmt.Errorf("shared bind not initialized")
	}

	m.stopDirectRelayLocked()

	listener, err := m.mainNetstack.ListenUDP(net.JoinHostPort(tunnelIP, fmt.Sprintf("%d", m.port)))
	if err != nil {
		return fmt.Errorf("listen on main tunnel netstack: %w", err)
	}

	m.sharedBind.SetNetstackConn(listener)
	m.relayStop = make(chan struct{})
	m.relayListener = listener
	m.relayWG.Add(1)
	go m.runDirectRelay(listener)

	m.logger.Info("clients direct relay started", "listen", net.JoinHostPort(tunnelIP, fmt.Sprintf("%d", m.port)))
	return nil
}

func (m *Manager) runDirectRelay(listener net.PacketConn) {
	defer m.relayWG.Done()

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-m.relayStop:
			return
		default:
		}

		_ = listener.SetReadDeadline(noLaterThanNowPlus100ms())
		n, remoteAddr, err := listener.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-m.relayStop:
				return
			default:
			}
			m.logger.Debug("clients direct relay read failed", "error", err)
			continue
		}

		udpAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok {
			m.logger.Debug("clients direct relay received unexpected addr type", "type", fmt.Sprintf("%T", remoteAddr))
			continue
		}

		addrPort := udpAddr.AddrPort()
		if addrPort.Addr().Is4In6() {
			addrPort = netipAddrPortUnmap(addrPort)
		}

		if err := m.sharedBind.InjectPacket(buf[:n], addrPort); err != nil {
			m.logger.Debug("clients direct relay inject failed", "error", err)
		}
	}
}

func (m *Manager) stopDirectRelayLocked() {
	if m.relayStop != nil {
		close(m.relayStop)
		m.relayWG.Wait()
		m.relayStop = nil
	}
	if m.sharedBind != nil {
		m.sharedBind.ClearNetstackConn()
	}
	if m.relayListener != nil {
		_ = m.relayListener.Close()
		m.relayListener = nil
	}
}
