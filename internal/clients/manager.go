// Package clients provides the foundational datapath for downstream client
// WireGuard traffic relayed through the main tunnel.
package clients

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/internal/bind"
	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/holepunch"
	"github.com/fosrl/newt/internal/netstack"
	"github.com/fosrl/newt/internal/tunnel"
	"github.com/fosrl/newt/internal/wgtester"
	wgDevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Manager owns the shared UDP socket used for downstream client communication.
// It currently provides the direct relay between the main tunnel netstack and
// the shared bind, which is the core missing datapath needed for client WG parity.
type Manager struct {
	logger *slog.Logger
	port   uint16
	mtu    int
	dns    string

	control *control.Client

	sharedBind *bind.SharedBind
	holePunch  *holepunch.Manager
	hpTester   *holepunch.Tester

	mu            sync.Mutex
	mainNetstack  *tunnel.NetStack
	relayStop     chan struct{}
	relayListener net.PacketConn
	relayWG       sync.WaitGroup

	privateKeyHex string
	publicKey     string
	device        *tunnel.Device
	clientTun     tun.Device
	clientNet     *netstack.Net
	tester        *wgtester.Server
	clientIP      string
	peers         map[string]control.ClientWGPeer
	appliedPeers  map[string]struct{}
	lastReadings  map[string]peerReading

	configRequestCancel context.CancelFunc
	configRequestWG     sync.WaitGroup
	configRequestEvery  time.Duration
	sendConfigRequestFn func(ctx context.Context) error
}

func (m *Manager) debug(msg string, args ...any) {
	if m.logger != nil {
		m.logger.Debug(msg, args...)
	}
}

type peerBandwidth struct {
	PublicKey string  `json:"publicKey"`
	BytesIn   float64 `json:"bytesIn"`
	BytesOut  float64 `json:"bytesOut"`
}

type peerReading struct {
	BytesReceived    int64
	BytesTransmitted int64
	LastChecked      time.Time
}

// NewManager creates a new client relay manager and its shared UDP socket.
func NewManager(port uint16, mtu int, dns string, controlClient *control.Client, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	privateKeyHex, publicKey, err := tunnel.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(port),
	})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	sharedBind, err := bind.New(udpConn)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("create shared bind: %w", err)
	}

	actualPort := sharedBind.GetPort()

	holePunch := holepunch.NewManager(controlClient.ConfigID(), "newt", publicKey, logger)
	holePunch.SetWriter(sharedBind)
	hpTester := holepunch.NewTester(sharedBind, logger)
	hpTester.SetCallback(func(status holepunch.HolepunchStatus) {
		if status.Connected {
			logger.Info("clients hole punch reachable", "endpoint", status.Endpoint, "rtt", status.RTT)
			return
		}
		logger.Warn("clients hole punch unreachable", "endpoint", status.Endpoint)
	})

	return &Manager{
		logger:     logger,
		port:       actualPort,
		mtu:        mtu,
		dns:        dns,
		control:    controlClient,
		sharedBind: sharedBind,
		holePunch:  holePunch,
		hpTester:   hpTester,
		privateKeyHex: privateKeyHex,
		publicKey:     publicKey,
		peers:       make(map[string]control.ClientWGPeer),
		appliedPeers: make(map[string]struct{}),
		lastReadings: make(map[string]peerReading),
		configRequestEvery: 2 * time.Second,
	}, nil
}

// Name implements lifecycle.Component.
func (m *Manager) Name() string {
	return "clients"
}

// Start implements lifecycle.Component.
func (m *Manager) Start(ctx context.Context) error {
	m.control.Register(control.MsgClientWGReceiveConfig, m.handleReceiveConfig)
	m.control.Register(control.MsgClientWGPeerAdd, m.handlePeerAdd)
	m.control.Register(control.MsgClientWGPeerRemove, m.handlePeerRemove)
	m.control.Register(control.MsgClientWGPeerUpdate, m.handlePeerUpdate)
	m.control.Register(control.MsgClientWGSync, m.handleSync)
	m.control.Register(control.MsgClientWGTargetsAdd, m.handleTargetsAdd)
	m.control.Register(control.MsgClientWGTargetsRemove, m.handleTargetsRemove)
	m.control.Register(control.MsgClientWGTargetsUpdate, m.handleTargetsUpdate)

	if m.holePunch != nil {
		go func() {
			if err := m.holePunch.Start(ctx); err != nil && err != context.Canceled {
				m.logger.Warn("hole punch manager stopped", "error", err)
			}
		}()
	}
	if m.hpTester != nil {
		if err := m.hpTester.Start(); err != nil {
			m.logger.Warn("hole punch tester failed to start", "error", err)
		}
	}

	go m.runBandwidthReporting(ctx)

	m.logger.Info("clients manager started", "port", m.port)
	<-ctx.Done()
	m.stopConfigRequests()
	m.Reset()
	if m.sharedBind != nil {
		_ = m.sharedBind.Close()
	}
	return ctx.Err()
}

// Port returns the port bound for downstream client communication.
func (m *Manager) Port() uint16 {
	return m.port
}

// SetToken updates the control-plane auth token used for legacy hole punching.
func (m *Manager) SetToken(token string) {
	if m.holePunch != nil {
		m.holePunch.SetToken(token)
	}
}

// PublicKey returns the downstream client WG public key.
func (m *Manager) PublicKey() string {
	return m.publicKey
}

// SharedBind returns the shared WireGuard bind for future client WG integration.
func (m *Manager) SharedBind() *bind.SharedBind {
	return m.sharedBind
}

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

// Reset stops any direct relay and clears main tunnel state.
func (m *Manager) Reset() {
	m.stopConfigRequests()
	if m.holePunch != nil {
		_ = m.holePunch.SyncExitNodes(nil)
	}
	if m.hpTester != nil {
		m.hpTester.Stop()
		_ = m.hpTester.Start()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopDirectRelayLocked()
	m.mainNetstack = nil
	m.closeClientInterfaceLocked()
}

// RequestConfig requests downstream client configuration from the control plane.
func (m *Manager) RequestConfig(ctx context.Context) error {
	if err := m.sendConfigRequest(ctx); err != nil {
		return err
	}

	m.startConfigRequestLoop()
	return nil
}

func (m *Manager) handleReceiveConfig(msg control.Message) error {
	var cfg control.ClientWGConfig
	if err := json.Unmarshal(msg.Data, &cfg); err != nil {
		return fmt.Errorf("unmarshal client wg config: %w", err)
	}

	m.stopConfigRequests()

	if err := m.ensureInterface(cfg.IpAddress); err != nil {
		return err
	}

	m.mu.Lock()
	m.peers = make(map[string]control.ClientWGPeer, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		m.peers[peer.PublicKey] = peer
	}
	m.mu.Unlock()

	if err := m.applyPeers(); err != nil {
		return err
	}

	if err := m.syncTargets(cfg.Targets); err != nil {
		return err
	}

	m.logger.Info("clients WG config applied",
		"ip_address", cfg.IpAddress,
		"peer_count", len(cfg.Peers),
		"target_count", len(cfg.Targets),
	)
	return nil
}

func (m *Manager) handlePeerAdd(msg control.Message) error {
	var peer control.ClientWGPeer
	if err := json.Unmarshal(msg.Data, &peer); err != nil {
		return fmt.Errorf("unmarshal client peer add: %w", err)
	}
	m.mu.Lock()
	m.peers[peer.PublicKey] = peer
	m.mu.Unlock()
	if m.holePunch != nil {
		_ = m.holePunch.TriggerHolePunch()
	}
	return m.applyPeers()
}

func (m *Manager) handlePeerRemove(msg control.Message) error {
	var data struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal client peer remove: %w", err)
	}
	m.mu.Lock()
	delete(m.peers, data.PublicKey)
	m.mu.Unlock()
	return m.applyPeers()
}

func (m *Manager) handlePeerUpdate(msg control.Message) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		return fmt.Errorf("unmarshal client peer update raw: %w", err)
	}

	var peer control.ClientWGPeer
	if err := json.Unmarshal(msg.Data, &peer); err != nil {
		return fmt.Errorf("unmarshal client peer update: %w", err)
	}
	_, endpointSpecified := raw["endpoint"]

	m.mu.Lock()
	existing := m.peers[peer.PublicKey]
	if len(peer.AllowedIPs) > 0 {
		existing.AllowedIPs = peer.AllowedIPs
	}
	if endpointSpecified || existing.PublicKey == "" {
		existing.Endpoint = peer.Endpoint
	}
	existing.PublicKey = peer.PublicKey
	m.peers[peer.PublicKey] = existing
	device := m.device
	m.mu.Unlock()
	if m.holePunch != nil {
		_ = m.holePunch.TriggerHolePunch()
	}
	if device != nil {
		prefixes, err := parseAllowedIPs(existing.AllowedIPs)
		if err != nil {
			return fmt.Errorf("parse allowed IPs for %s: %w", existing.PublicKey, err)
		}
		if endpointSpecified && existing.Endpoint == "" {
			if err := device.RemovePeer(existing.PublicKey); err != nil {
				return fmt.Errorf("remove peer %s for endpoint clear: %w", existing.PublicKey, err)
			}
			if err := device.AddPeer(tunnel.PeerConfig{
				PublicKey:           existing.PublicKey,
				Endpoint:            "",
				AllowedIPs:          prefixes,
				PersistentKeepalive: 25,
			}); err != nil {
				return fmt.Errorf("re-add peer %s after endpoint clear: %w", existing.PublicKey, err)
			}
			return nil
		}
		if err := device.UpdatePeer(tunnel.PeerConfig{
			PublicKey:           existing.PublicKey,
			Endpoint:            existing.Endpoint,
			AllowedIPs:          prefixes,
			PersistentKeepalive: 25,
		}, endpointSpecified); err != nil {
			return fmt.Errorf("update peer %s: %w", existing.PublicKey, err)
		}
		return nil
	}
	return m.applyPeers()
}

func (m *Manager) handleSync(msg control.Message) error {
	var cfg struct {
		Targets []control.ClientWGTarget `json:"targets"`
		Peers   []control.ClientWGPeer   `json:"peers"`
	}
	if err := json.Unmarshal(msg.Data, &cfg); err != nil {
		return fmt.Errorf("unmarshal client sync: %w", err)
	}
	m.mu.Lock()
	m.peers = make(map[string]control.ClientWGPeer, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		m.peers[peer.PublicKey] = peer
	}
	m.mu.Unlock()
	if err := m.syncTargets(cfg.Targets); err != nil {
		return err
	}
	return m.applyPeers()
}

func (m *Manager) ensureInterface(ipAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ipAddress == m.clientIP && m.device != nil && m.clientNet != nil && m.clientTun != nil {
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

	tunDev, ns, err := netstack.CreateTUN([]netip.Addr{addr}, []netip.Addr{dnsIP}, m.mtu)
	if err != nil {
		return fmt.Errorf("create client netstack: %w", err)
	}

	logger := &wgDevice.Logger{
		Verbosef: func(format string, args ...any) { m.logger.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { m.logger.Error(fmt.Sprintf(format, args...)) },
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
	m.logger.Info("clients wg tester started", "listen", fmt.Sprintf(":%d", m.port+1), "client_ip", ipAddress)

	m.clientIP = ipAddress
	m.clientTun = tunDev
	m.clientNet = ns
	m.device = device
	m.tester = tester
	return nil
}

func (m *Manager) applyPeers() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.device == nil {
		return nil
	}

	current := make([]control.ClientWGPeer, 0, len(m.peers))
	for _, peer := range m.peers {
		current = append(current, peer)
	}

	for publicKey := range m.appliedPeers {
		if _, ok := m.peers[publicKey]; !ok {
			if err := m.device.RemovePeer(publicKey); err != nil {
				m.logger.Warn("failed to remove stale client peer", "public_key", publicKey, "error", err)
			}
			delete(m.appliedPeers, publicKey)
		}
	}

	for _, peer := range current {
		prefixes, err := parseAllowedIPs(peer.AllowedIPs)
		if err != nil {
			return fmt.Errorf("parse allowed IPs for %s: %w", peer.PublicKey, err)
		}
		if err := m.device.AddPeer(tunnel.PeerConfig{
			PublicKey:           peer.PublicKey,
			Endpoint:            peer.Endpoint,
			AllowedIPs:          prefixes,
			PersistentKeepalive: 25,
		}); err != nil {
			return fmt.Errorf("add peer %s: %w", peer.PublicKey, err)
		}
		m.appliedPeers[peer.PublicKey] = struct{}{}
	}

	return nil
}

// StartHolepunch configures the active exit-node relay target used for
// downstream client hole punching.
func (m *Manager) StartHolepunch(publicKey, endpoint string, relayPort uint16) error {
	if m.holePunch == nil {
		return nil
	}
	if relayPort == 0 {
		relayPort = 21820
	}
	if err := m.holePunch.SyncExitNodes([]holepunch.ExitNode{
		{
			ID:        publicKey,
			Name:      publicKey,
			Endpoint:  endpoint,
			RelayPort: relayPort,
			PublicKey: publicKey,
			Active:    true,
		},
	}); err != nil {
		return err
	}
	m.logger.Info("clients hole punch target configured", "endpoint", endpoint, "relay_port", relayPort, "public_key", publicKey)

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

func (m *Manager) handleTargetsAdd(msg control.Message) error {
	var targets []control.ClientWGTarget
	if err := json.Unmarshal(msg.Data, &targets); err != nil {
		return fmt.Errorf("unmarshal client target add: %w", err)
	}
	return m.addTargets(targets)
}

func (m *Manager) handleTargetsRemove(msg control.Message) error {
	var targets []control.ClientWGTarget
	if err := json.Unmarshal(msg.Data, &targets); err != nil {
		return fmt.Errorf("unmarshal client target remove: %w", err)
	}
	return m.removeTargets(targets)
}

func (m *Manager) handleTargetsUpdate(msg control.Message) error {
	var data struct {
		OldTargets []control.ClientWGTarget `json:"oldTargets"`
		NewTargets []control.ClientWGTarget `json:"newTargets"`
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal client target update: %w", err)
	}
	if err := m.removeTargets(data.OldTargets); err != nil {
		return err
	}
	return m.addTargets(data.NewTargets)
}

func (m *Manager) addTargets(targets []control.ClientWGTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.clientNet == nil {
		return nil
	}

	for _, target := range targets {
		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			return fmt.Errorf("parse dest prefix %s: %w", target.DestPrefix, err)
		}

		portRanges := toProxyPortRanges(target.PortRange)
		for _, source := range resolveSourcePrefixes(target) {
			sourcePrefix, err := netip.ParsePrefix(source)
			if err != nil {
				return fmt.Errorf("parse source prefix %s: %w", source, err)
			}
			m.clientNet.AddProxySubnetRule(sourcePrefix, destPrefix, target.RewriteTo, portRanges, target.DisableIcmp)
		}
	}

	return nil
}

func (m *Manager) removeTargets(targets []control.ClientWGTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.clientNet == nil {
		return nil
	}

	for _, target := range targets {
		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			return fmt.Errorf("parse dest prefix %s: %w", target.DestPrefix, err)
		}

		for _, source := range resolveSourcePrefixes(target) {
			sourcePrefix, err := netip.ParsePrefix(source)
			if err != nil {
				return fmt.Errorf("parse source prefix %s: %w", source, err)
			}
			m.clientNet.RemoveProxySubnetRule(sourcePrefix, destPrefix)
		}
	}

	return nil
}

func (m *Manager) syncTargets(targets []control.ClientWGTarget) error {
	m.mu.Lock()
	if m.clientNet == nil {
		m.mu.Unlock()
		return nil
	}

	currentRules := m.clientNet.ProxySubnetRules()
	for _, rule := range currentRules {
		m.clientNet.RemoveProxySubnetRule(rule.SourcePrefix, rule.DestPrefix)
	}
	m.mu.Unlock()

	return m.addTargets(targets)
}

func resolveSourcePrefixes(target control.ClientWGTarget) []string {
	if len(target.SourcePrefixes) > 0 {
		return target.SourcePrefixes
	}
	if target.SourcePrefix != "" {
		return []string{target.SourcePrefix}
	}
	return nil
}

func toProxyPortRanges(ranges []control.ClientWGPortRange) []netstack.PortRange {
	if len(ranges) == 0 {
		return nil
	}

	out := make([]netstack.PortRange, 0, len(ranges))
	for _, pr := range ranges {
		out = append(out, netstack.PortRange{
			Min:      pr.Min,
			Max:      pr.Max,
			Protocol: pr.Protocol,
		})
	}
	return out
}

func (m *Manager) sendConfigRequest(ctx context.Context) error {
	if m.sendConfigRequestFn != nil {
		return m.sendConfigRequestFn(ctx)
	}
	return m.control.SendData(ctx, control.MsgClientWGGetConfig, control.ClientWGGetConfigData{
		PublicKey: m.PublicKey(),
		Port:      m.port,
	})
}

func (m *Manager) startConfigRequestLoop() {
	m.mu.Lock()
	if m.configRequestCancel != nil {
		m.configRequestCancel()
		m.mu.Unlock()
		m.configRequestWG.Wait()
		m.mu.Lock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.configRequestCancel = cancel
	m.configRequestWG.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.configRequestWG.Done()

		interval := m.configRequestEvery
		if interval <= 0 {
			interval = 2 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if m.sendConfigRequestFn == nil && (m.control == nil || !m.control.Connected()) {
					continue
				}
				sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := m.sendConfigRequest(sendCtx)
				sendCancel()
				if err != nil {
					m.logger.Debug("client WG config request failed", "error", err)
				}
			}
		}
	}()
}

func (m *Manager) stopConfigRequests() {
	m.mu.Lock()
	cancel := m.configRequestCancel
	m.configRequestCancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		m.configRequestWG.Wait()
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

func (m *Manager) runBandwidthReporting(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.reportPeerBandwidth(ctx); err != nil {
				m.logger.Debug("failed to report peer bandwidth", "error", err)
			}
		}
	}
}

func (m *Manager) reportPeerBandwidth(ctx context.Context) error {
	bandwidths, err := m.calculatePeerBandwidth()
	if err != nil {
		return err
	}
	if len(bandwidths) == 0 {
		return nil
	}

	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return m.control.SendData(sendCtx, control.MsgReceiveBandwidth, map[string]any{
		"bandwidthData": bandwidths,
	})
}

func (m *Manager) calculatePeerBandwidth() ([]peerBandwidth, error) {
	m.mu.Lock()
	device := m.device
	m.mu.Unlock()

	if device == nil {
		return nil, nil
	}

	stats, err := device.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("get client WG stats: %w", err)
	}

	now := time.Now()
	bandwidths := make([]peerBandwidth, 0)

	m.mu.Lock()
	defer m.mu.Unlock()

	lines := strings.Split(stats, "\n")
	var currentPubKey string
	var rxBytes, txBytes int64
	devicePeers := make(map[string]struct{})

	processCurrent := func() {
		if currentPubKey == "" {
			return
		}
		if bw := m.processPeerBandwidth(currentPubKey, rxBytes, txBytes, now); bw != nil {
			bandwidths = append(bandwidths, *bw)
		}
	}

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "public_key="):
			processCurrent()
			currentPubKey = strings.TrimPrefix(line, "public_key=")
			devicePeers[currentPubKey] = struct{}{}
			rxBytes = 0
			txBytes = 0
		case strings.HasPrefix(line, "rx_bytes="):
			rxBytes, _ = strconv.ParseInt(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		case strings.HasPrefix(line, "tx_bytes="):
			txBytes, _ = strconv.ParseInt(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		}
	}
	processCurrent()

	for publicKey := range m.lastReadings {
		if _, ok := devicePeers[publicKey]; !ok {
			delete(m.lastReadings, publicKey)
		}
	}

	return bandwidths, nil
}

func (m *Manager) processPeerBandwidth(publicKey string, rxBytes, txBytes int64, now time.Time) *peerBandwidth {
	current := peerReading{
		BytesReceived:    rxBytes,
		BytesTransmitted: txBytes,
		LastChecked:      now,
	}

	last, ok := m.lastReadings[publicKey]
	m.lastReadings[publicKey] = current
	if !ok {
		return nil
	}

	if !current.LastChecked.After(last.LastChecked) {
		return nil
	}

	bytesInDiff := float64(current.BytesReceived - last.BytesReceived)
	bytesOutDiff := float64(current.BytesTransmitted - last.BytesTransmitted)
	if bytesInDiff < 0 {
		bytesInDiff = float64(current.BytesReceived)
	}
	if bytesOutDiff < 0 {
		bytesOutDiff = float64(current.BytesTransmitted)
	}
	if bytesInDiff == 0 && bytesOutDiff == 0 {
		return nil
	}

	return &peerBandwidth{
		PublicKey: normalizeIPCKeyToBase64(publicKey),
		BytesIn:   bytesInDiff / (1024 * 1024),
		BytesOut:  bytesOutDiff / (1024 * 1024),
	}
}

func normalizeIPCKeyToBase64(publicKey string) string {
	keyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return publicKey
	}
	return base64.StdEncoding.EncodeToString(keyBytes)
}
