// Package clients provides the foundational datapath for downstream client
// WireGuard traffic relayed through the main tunnel.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/fosrl/newt/internal/bind"
	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/holepunch"
	"github.com/fosrl/newt/internal/netstack"
	"github.com/fosrl/newt/internal/tunnel"
	"github.com/fosrl/newt/internal/wgtester"
	"golang.zx2c4.com/wireguard/tun"
)

// Manager coordinates downstream client WireGuard state, relay, and hole-punch
// behavior over the shared UDP socket.
type Manager struct {
	logger *slog.Logger
	port   uint16
	mtu    int
	dns    string
	iface  string
	native bool

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
func NewManager(port uint16, mtu int, dns, iface string, native bool, controlClient *control.Client, logger *slog.Logger) (*Manager, error) {
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
		_ = udpConn.Close()
		return nil, fmt.Errorf("create shared bind: %w", err)
	}

	actualPort := sharedBind.GetPort()

	holePunch := holepunch.NewManager(controlClient.ConfigID(), "newt", publicKey, logger)
	holePunch.SetWriter(sharedBind)
	hpTester := holepunch.NewTester(sharedBind, logger)
	hpTester.SetCallback(func(status holepunch.HolepunchStatus) {
		if status.Connected {
			logger.Debug("clients hole punch reachable", "endpoint", status.Endpoint, "rtt", status.RTT)
			return
		}
		logger.Debug("clients hole punch unreachable", "endpoint", status.Endpoint)
	})

	return &Manager{
		logger:             logger,
		port:               actualPort,
		mtu:                mtu,
		dns:                dns,
		iface:              iface,
		native:             native,
		control:            controlClient,
		sharedBind:         sharedBind,
		holePunch:          holePunch,
		hpTester:           hpTester,
		privateKeyHex:      privateKeyHex,
		publicKey:          publicKey,
		peers:              make(map[string]control.ClientWGPeer),
		appliedPeers:       make(map[string]struct{}),
		lastReadings:       make(map[string]peerReading),
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
	m.shutdown()
	return ctx.Err()
}

// Port returns the port bound for downstream client communication.
func (m *Manager) Port() uint16 {
	return m.port
}

// SetToken updates the control-plane auth token used for hole punching.
func (m *Manager) SetToken(token string) {
	if m.holePunch != nil {
		m.holePunch.SetToken(token)
	}
}

// PublicKey returns the downstream client WG public key.
func (m *Manager) PublicKey() string {
	return m.publicKey
}

// SharedBind returns the shared WireGuard bind used by the client datapath.
func (m *Manager) SharedBind() *bind.SharedBind {
	return m.sharedBind
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

func (m *Manager) shutdown() {
	m.stopConfigRequests()
	if m.holePunch != nil {
		_ = m.holePunch.SyncExitNodes(nil)
	}
	if m.hpTester != nil {
		m.hpTester.Stop()
	}

	m.mu.Lock()
	m.stopDirectRelayLocked()
	m.mainNetstack = nil
	m.closeClientInterfaceLocked()
	m.mu.Unlock()

	if m.sharedBind != nil {
		_ = m.sharedBind.Close()
	}
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

	m.replacePeers(cfg.Peers)

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
	m.storePeer(peer)
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
	m.deletePeer(data.PublicKey)
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

	existing, device := m.mergePeerUpdate(peer, endpointSpecified)
	if m.holePunch != nil {
		_ = m.holePunch.TriggerHolePunch()
	}
	return m.applyPeerUpdate(existing, endpointSpecified, device)
}

func (m *Manager) handleSync(msg control.Message) error {
	var cfg struct {
		Targets []control.ClientWGTarget `json:"targets"`
		Peers   []control.ClientWGPeer   `json:"peers"`
	}
	if err := json.Unmarshal(msg.Data, &cfg); err != nil {
		return fmt.Errorf("unmarshal client sync: %w", err)
	}
	m.replacePeers(cfg.Peers)
	if err := m.syncTargets(cfg.Targets); err != nil {
		return err
	}
	return m.applyPeers()
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
