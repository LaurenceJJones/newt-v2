package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/lifecycle"
)

// Manager coordinates the WireGuard tunnel lifecycle.
type Manager struct {
	cfg    Config
	logger *slog.Logger

	// Control plane client for receiving commands
	control *control.Client
	ctx     context.Context

	// WireGuard keys (generated at startup)
	privateKeyHex   string
	publicKeyBase64 string

	// Current tunnel state
	tunnel         atomic.Pointer[activeTunnel]
	state          atomic.Int32 // TunnelState
	recoveryActive atomic.Bool

	// Callbacks
	onConnect    func(info TunnelInfo)
	onDisconnect func()

	// Test seams for recovery behavior.
	sendControlData func(ctx context.Context, msgType string, data any) error
	recoveryEvery   time.Duration
}

// activeTunnel represents an active tunnel instance.
type activeTunnel struct {
	device       *Device
	netstack     *NetStack
	peerKey      string
	peerEndpoint string
	relayPort    uint16
	localIP      netip.Addr
	connectData  control.WgConnectData

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	group  *lifecycle.Group
}

// NewManager creates a new tunnel manager.
func NewManager(cfg Config, controlClient *control.Client, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	// Generate WireGuard keys at startup
	privateKeyHex, publicKeyBase64, err := generateKeyPair()
	if err != nil {
		logger.Error("failed to generate wireguard keys", "error", err)
		// Generate anyway - this will fail later but we can still create the manager
		privateKeyHex = ""
		publicKeyBase64 = ""
	}

	m := &Manager{
		cfg:             cfg,
		logger:          logger,
		control:         controlClient,
		privateKeyHex:   privateKeyHex,
		publicKeyBase64: publicKeyBase64,
	}

	m.state.Store(int32(StateDisconnected))

	logger.Debug("wireguard keys generated", "public_key", publicKeyBase64)

	return m
}

// PublicKey returns the manager's WireGuard public key in base64.
func (m *Manager) PublicKey() string {
	return m.publicKeyBase64
}

// OnConnect sets a callback for when a tunnel connects.
func (m *Manager) OnConnect(fn func(info TunnelInfo)) {
	m.onConnect = fn
}

// OnDisconnect sets a callback for when a tunnel disconnects.
func (m *Manager) OnDisconnect(fn func()) {
	m.onDisconnect = fn
}

// Name returns the component name.
func (m *Manager) Name() string {
	return "tunnel"
}

// Start initializes the tunnel manager and registers handlers.
func (m *Manager) Start(ctx context.Context) error {
	m.ctx = ctx

	// Register message handlers
	m.control.Register(control.MsgWgConnect, m.handleConnect)
	m.control.Register(control.MsgWgReconnect, m.handleReconnect)
	m.control.Register(control.MsgWgTerminate, m.handleTerminate)

	m.logger.Info("tunnel manager started")

	// Wait for context cancellation
	<-ctx.Done()

	// Clean up
	m.closeTunnel(StateDisconnected)

	return ctx.Err()
}

// handleConnect handles the WireGuard connect message.
func (m *Manager) handleConnect(msg control.Message) error {
	var data control.WgConnectData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal connect data: %w", err)
	}

	if current := m.tunnel.Load(); current != nil && current.device != nil && reflect.DeepEqual(current.connectData, data) {
		m.logger.Info("received identical connect command; keeping existing tunnel",
			"endpoint", data.Endpoint,
			"server_ip", data.ServerIP,
		)
		return nil
	}

	m.logger.Info("received connect command",
		"endpoint", data.Endpoint,
		"server_ip", data.ServerIP,
	)

	// Parse tunnel IP
	tunnelIP, err := netip.ParseAddr(data.TunnelIP)
	if err != nil {
		return fmt.Errorf("parse tunnel ip %q: %w", data.TunnelIP, err)
	}

	// Parse DNS
	dnsIP, err := netip.ParseAddr(m.cfg.DNS)
	if err != nil {
		dnsIP = netip.MustParseAddr("9.9.9.9")
	}

	// Close existing tunnel if any
	m.closeTunnel(StateDisconnected)

	// Create new tunnel
	m.state.Store(int32(StateConnecting))

	tunnel, err := m.createTunnel(tunnelIP, dnsIP, data)
	if err != nil {
		m.logger.Warn("failed to create tunnel", "error", err)
		m.requestRecovery("tunnel creation failed")
		return nil
	}

	m.tunnel.Store(tunnel)
	m.state.Store(int32(StateConnected))

	// Notify callback with initial targets
	if m.onConnect != nil {
		info := TunnelInfo{
			State:             StateConnected,
			LocalAddr:         tunnelIP,
			PeerKey:           data.PublicKey,
			PeerEndpoint:      tunnel.peerEndpoint,
			RelayPort:         data.RelayPort,
			InitialTCPTargets: data.Targets.TCP,
			InitialUDPTargets: data.Targets.UDP,
		}

		// Convert health checks
		for _, hc := range data.HealthCheckTargets {
			info.InitialHealthChecks = append(info.InitialHealthChecks, HealthCheckInfo{
				TargetID:          hc.ID,
				Hostname:          hc.Hostname,
				Port:              hc.Port,
				Path:              hc.Path,
				Scheme:            hc.Scheme,
				Mode:              hc.Mode,
				Method:            hc.Method,
				ExpectedStatus:    hc.Status,
				Headers:           hc.Headers,
				Interval:          hc.Interval,
				UnhealthyInterval: hc.UnhealthyInterval,
				Timeout:           hc.Timeout,
				TLSServerName:     hc.TLSServerName,
				Enabled:           hc.Enabled,
			})
		}

		m.onConnect(info)
	}

	m.logger.Info("tunnel connected",
		"local_ip", tunnelIP,
		"peer", data.PublicKey[:8]+"...",
	)

	return nil
}

// createTunnel sets up a new WireGuard tunnel.
func (m *Manager) createTunnel(localIP, dnsIP netip.Addr, data control.WgConnectData) (*activeTunnel, error) {
	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	group := lifecycle.NewGroup(ctx)

	// Create netstack
	ns, err := NewNetStack(NetStackConfig{
		LocalAddr: localIP,
		DNS:       dnsIP,
		MTU:       m.cfg.MTU,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create netstack: %w", err)
	}

	// Create WireGuard device
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			m.logger.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			m.logger.Error(fmt.Sprintf(format, args...))
		},
	}

	// Use standard bind for now
	bind := conn.NewDefaultBind()

	wgDevice, err := NewDevice(ns.Device(), bind, wgLogger, m.privateKeyHex)
	if err != nil {
		cancel()
		ns.Close()
		return nil, fmt.Errorf("create wireguard device: %w", err)
	}

	resolvedEndpoint, err := resolveEndpoint(data.Endpoint)
	if err != nil {
		cancel()
		wgDevice.Close()
		ns.Close()
		return nil, fmt.Errorf("resolve peer endpoint: %w", err)
	}

	serverPrefix, err := serverAllowedPrefix(data.ServerIP)
	if err != nil {
		cancel()
		wgDevice.Close()
		ns.Close()
		return nil, fmt.Errorf("parse server allowed IP: %w", err)
	}

	// Configure peer
	peerCfg := PeerConfig{
		PublicKey: data.PublicKey,
		Endpoint:  resolvedEndpoint,
		AllowedIPs: []netip.Prefix{
			serverPrefix,
		},
		PersistentKeepalive: 5,
	}

	if err := wgDevice.AddPeer(peerCfg); err != nil {
		cancel()
		wgDevice.Close()
		ns.Close()
		return nil, fmt.Errorf("add peer: %w", err)
	}

	// Bring device up
	if err := wgDevice.Up(); err != nil {
		cancel()
		wgDevice.Close()
		ns.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}

	tunnel := &activeTunnel{
		device:       wgDevice,
		netstack:     ns,
		peerKey:      data.PublicKey,
		peerEndpoint: data.Endpoint,
		relayPort:    data.RelayPort,
		localIP:      localIP,
		connectData:  data,
		ctx:          ctx,
		cancel:       cancel,
		group:        group,
	}

	// Start ping check goroutine
	group.Go(func(ctx context.Context) error {
		return m.runPingCheck(ctx, tunnel, data.ServerIP)
	})

	return tunnel, nil
}

// runPingCheck continuously pings the server to verify tunnel health.
func (m *Manager) runPingCheck(ctx context.Context, t *activeTunnel, serverIP string) error {
	interval := m.cfg.PingInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	consecutiveFailures := 0

	// Initial ping
	if err := m.ping(ctx, t, serverIP); err != nil {
		m.logger.Warn("initial ping failed", "error", err)
		consecutiveFailures++
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := m.ping(ctx, t, serverIP); err != nil {
				consecutiveFailures++
				m.logger.Warn("ping failed",
					"consecutive_failures", consecutiveFailures,
					"error", err,
				)
				if consecutiveFailures >= 4 {
					go m.requestRecovery("tunnel health checks failed")
					return nil
				}
				continue
			}
			consecutiveFailures = 0
		}
	}
}

// ping performs an ICMP ping through the tunnel.
func (m *Manager) ping(ctx context.Context, t *activeTunnel, serverIP string) error {
	timeout := m.cfg.PingTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	latency, err := t.netstack.Ping(ctx, serverIP, timeout)
	if err != nil {
		return err
	}

	m.logger.Debug("ping successful", "server", serverIP, "latency", latency)
	return nil
}

// handleReconnect handles the reconnect message.
func (m *Manager) handleReconnect(msg control.Message) error {
	m.logger.Info("received reconnect command")
	go m.requestRecovery("server requested reconnect")
	return nil
}

// handleTerminate handles the terminate message.
func (m *Manager) handleTerminate(msg control.Message) error {
	m.logger.Info("received terminate command")
	m.closeTunnel(StateDisconnected)
	return nil
}

// closeTunnel shuts down the current tunnel if active.
func (m *Manager) closeTunnel(nextState TunnelState) {
	t := m.tunnel.Swap(nil)
	m.state.Store(int32(nextState))
	if t == nil {
		return
	}

	m.logger.Debug("closing tunnel")

	// Cancel context to stop goroutines
	t.cancel()

	// Wait for goroutines with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		t.group.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Debug("tunnel goroutines stopped")
	case <-ctx.Done():
		m.logger.Warn("tunnel goroutines did not stop in time")
	}

	// Close WireGuard device
	t.device.Close()

	// Notify callback
	if m.onDisconnect != nil {
		m.onDisconnect()
	}

	m.logger.Info("tunnel closed")
}

func serverAllowedPrefix(serverIP string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(serverIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse server ip %q: %w", serverIP, err)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func (m *Manager) requestRecovery(reason string) {
	m.closeTunnel(StateReconnecting)

	if !m.recoveryActive.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer m.recoveryActive.Store(false)

		interval := m.recoveryEvery
		if interval <= 0 {
			interval = 3 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		firstAttempt := true
		registerSent := false
		for {
			if m.ctx == nil {
				return
			}

			select {
			case <-m.ctx.Done():
				return
			default:
			}

			if m.State() != StateReconnecting || m.tunnel.Load() != nil {
				return
			}

			controlConnected := m.control != nil && m.control.Connected()
			if m.sendControlData != nil {
				controlConnected = true
			}
			if !controlConnected {
				if firstAttempt {
					m.logger.Info("waiting for control plane before tunnel recovery", "reason", reason)
					firstAttempt = false
				}
			} else {
				sendControlData := m.sendControlData
				if sendControlData == nil {
					sendControlData = m.control.SendData
				}

				if !registerSent {
					sendCtx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
					err := sendControlData(sendCtx, control.MsgWgRegister, control.WgRegisterData{
						PublicKey:           m.PublicKey(),
						BackwardsCompatible: true,
					})
					cancel()
					if err != nil {
						m.logger.Warn("failed to send recovery registration", "reason", reason, "error", err)
					} else {
						registerSent = true
					}
				}

				sendCtx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
				err := sendControlData(sendCtx, control.MsgPingRequest, control.PingRequestData{
					NoCloud: m.cfg.NoCloud,
				})
				cancel()

				if err != nil {
					m.logger.Warn("failed to request tunnel recovery", "reason", reason, "error", err)
				} else if firstAttempt {
					m.logger.Info("requested tunnel recovery", "reason", reason)
					firstAttempt = false
				}
			}

			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// State returns the current tunnel state.
func (m *Manager) State() TunnelState {
	return TunnelState(m.state.Load())
}

// Info returns information about the current tunnel.
func (m *Manager) Info() (TunnelInfo, error) {
	t := m.tunnel.Load()
	if t == nil {
		return TunnelInfo{State: TunnelState(m.state.Load())}, nil
	}

	return TunnelInfo{
		State:        TunnelState(m.state.Load()),
		LocalAddr:    t.localIP,
		PeerKey:      t.peerKey,
		PeerEndpoint: t.peerEndpoint,
		RelayPort:    t.relayPort,
	}, nil
}

// NetStack returns the current tunnel's netstack, or nil if not connected.
func (m *Manager) NetStack() *NetStack {
	t := m.tunnel.Load()
	if t == nil {
		return nil
	}
	return t.netstack
}

// Shutdown gracefully shuts down the tunnel manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.closeTunnel(StateDisconnected)
	return nil
}

// ErrNotConnected is returned when an operation requires an active tunnel.
var ErrNotConnected = errors.New("tunnel not connected")
