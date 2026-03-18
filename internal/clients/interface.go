package clients

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/fosrl/newt/internal/netstack"
	"github.com/fosrl/newt/internal/tunnel"
	"github.com/fosrl/newt/internal/wgtester"
	pkglogger "github.com/fosrl/newt/pkg/logger"
	wgDevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func (m *Manager) ensureInterface(ipAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ipAddress == m.clientIP && m.device != nil && m.clientTun != nil && (m.clientNet != nil || m.native) {
		return nil
	}

	m.closeClientInterfaceLocked()

	addr, err := parseCIDRAddr(ipAddress)
	if err != nil {
		return err
	}
	dnsIP, err := netip.ParseAddr(m.dns)
	if err != nil {
		dnsIP = netip.MustParseAddr("9.9.9.9")
	}

	if m.native {
		return m.ensureNativeInterfaceLocked(ipAddress)
	}

	tunDev, ns, err := netstack.CreateTUN([]netip.Addr{addr}, []netip.Addr{dnsIP}, m.mtu)
	if err != nil {
		return fmt.Errorf("create client netstack: %w", err)
	}

	logger := &wgDevice.Logger{
		Verbosef: func(format string, args ...any) { pkglogger.Debugf(m.logger, format, args...) },
		Errorf:   func(format string, args ...any) { pkglogger.Errorf(m.logger, format, args...) },
	}

	m.sharedBind.AddRef()
	device, err := tunnel.NewDevice(tunDev, m.sharedBind, logger, m.privateKeyHex)
	if err != nil {
		_ = m.sharedBind.Release()
		_ = tunDev.Close()
		return fmt.Errorf("create client wireguard device: %w", err)
	}
	if err := device.Up(); err != nil {
		device.Close()
		_ = tunDev.Close()
		return fmt.Errorf("bring up client wireguard device: %w", err)
	}

	testerConn, err := ns.ListenUDPAddr(&net.UDPAddr{Port: int(m.port + 1)})
	if err != nil {
		device.Close()
		_ = tunDev.Close()
		return fmt.Errorf("start wg tester listener: %w", err)
	}
	tester := wgtester.New(testerConn, m.port, m.logger)
	if err := tester.Start(); err != nil {
		_ = testerConn.Close()
		device.Close()
		_ = tunDev.Close()
		return fmt.Errorf("start wg tester: %w", err)
	}
	m.logger.Info("clients wg tester started", "port", m.port+1, "client_ip", ipAddress)

	m.clientIP = ipAddress
	m.clientTun = tunDev
	m.clientNet = ns
	m.device = device
	m.tester = tester
	return nil
}

func (m *Manager) ensureNativeInterfaceLocked(ipAddress string) error {
	if err := checkNativeInterfacePermissions(); err != nil {
		return err
	}

	tunDev, err := tun.CreateTUN(m.iface, m.mtu)
	if err != nil {
		return fmt.Errorf("create native tun: %w", err)
	}

	logger := &wgDevice.Logger{
		Verbosef: func(format string, args ...any) { pkglogger.Debugf(m.logger, format, args...) },
		Errorf:   func(format string, args ...any) { pkglogger.Errorf(m.logger, format, args...) },
	}

	m.sharedBind.AddRef()
	device, err := tunnel.NewDevice(tunDev, m.sharedBind, logger, m.privateKeyHex)
	if err != nil {
		_ = m.sharedBind.Release()
		_ = tunDev.Close()
		return fmt.Errorf("create native client wireguard device: %w", err)
	}
	if err := device.Up(); err != nil {
		device.Close()
		_ = tunDev.Close()
		return fmt.Errorf("bring up native client wireguard device: %w", err)
	}

	ifaceName := m.iface
	if name, err := tunDev.Name(); err == nil && name != "" {
		ifaceName = name
	}
	if err := configureNativeInterface(ifaceName, ipAddress, m.mtu); err != nil {
		device.Close()
		_ = tunDev.Close()
		return err
	}

	testerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: int(m.port + 1)})
	if err != nil {
		device.Close()
		_ = tunDev.Close()
		return fmt.Errorf("start native wg tester listener: %w", err)
	}
	tester := wgtester.New(testerConn, m.port, m.logger)
	if err := tester.Start(); err != nil {
		_ = testerConn.Close()
		device.Close()
		_ = tunDev.Close()
		return fmt.Errorf("start native wg tester: %w", err)
	}

	m.logger.Info("clients native wg interface started", "interface", ifaceName, "port", m.port, "client_ip", ipAddress)

	m.clientIP = ipAddress
	m.clientTun = tunDev
	m.clientNet = nil
	m.device = device
	m.tester = tester
	return nil
}

func (m *Manager) closeClientInterfaceLocked() {
	if m.tester != nil {
		m.tester.Stop()
		m.tester = nil
	}
	if m.device != nil {
		m.device.Close()
		m.device = nil
	}
	if m.clientTun != nil {
		_ = m.clientTun.Close()
		m.clientTun = nil
	}
	if m.clientNet != nil {
		m.clientNet = nil
	}
	m.clientIP = ""
	m.appliedPeers = make(map[string]struct{})
	m.lastReadings = make(map[string]peerReading)
}
