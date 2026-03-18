package expose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/lifecycle"
	"github.com/fosrl/newt/internal/telemetry"
)

// Manager coordinates TCP and UDP proxies for all targets.
type Manager struct {
	logger *slog.Logger
	updown string

	// Control plane client for receiving commands
	controlClient *control.Client

	// Dialer for creating connections (set when tunnel connects)
	mu       sync.RWMutex
	dialer   NetDialer
	listenIP string

	// Active proxies
	proxies map[TargetKey]*activeProxy
	pending []Target

	// Lifecycle
	group *lifecycle.Group
}

// activeProxy tracks a running proxy.
type activeProxy struct {
	target  Target
	tcp     *TCPProxy
	udp     *UDPProxy
	cancel  context.CancelFunc
	stopped chan struct{}
}

func targetKey(target Target) TargetKey {
	return TargetKey{Protocol: target.Protocol, ListenAddr: target.ListenAddr}
}

// NewManager creates a new proxy manager.
func NewManager(controlClient *control.Client, updown string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		logger:        logger,
		updown:        updown,
		controlClient: controlClient,
		proxies:       make(map[TargetKey]*activeProxy),
	}
}

// Name returns the component name.
func (m *Manager) Name() string {
	return "proxy"
}

// Start initializes the proxy manager and registers handlers.
func (m *Manager) Start(ctx context.Context) error {
	m.group = lifecycle.NewGroup(ctx)
	m.flushPendingTargets()

	m.registerHandlers()

	m.logger.Info("proxy manager started")

	// Wait for context cancellation
	<-ctx.Done()

	// Stop all proxies
	m.stopAll()

	return ctx.Err()
}

func (m *Manager) registerHandlers() {
	if m.controlClient == nil {
		return
	}

	m.controlClient.Register(control.MsgTCPAdd, m.handleAddTCP)
	m.controlClient.Register(control.MsgTCPRemove, m.handleRemoveTCP)
	m.controlClient.Register(control.MsgUDPAdd, m.handleAddUDP)
	m.controlClient.Register(control.MsgUDPRemove, m.handleRemoveUDP)
}

// SetDialer sets the dialer used for outbound proxy connections.
func (m *Manager) SetDialer(dialer NetDialer) {
	m.mu.Lock()
	m.dialer = dialer
	m.mu.Unlock()

	m.flushPendingTargets()
	m.logger.Debug("dialer set")
}

// SetListenIP sets the tunnel interface IP used for proxy listeners.
func (m *Manager) SetListenIP(ip string) {
	m.mu.Lock()
	m.listenIP = ip
	m.mu.Unlock()
}

// ListenIP returns the currently configured listen IP for proxy listeners.
func (m *Manager) ListenIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listenIP
}

// PendingCount returns the number of queued targets waiting for the proxy manager
// to become ready.
func (m *Manager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending)
}

// Reset clears all active and pending targets and removes the current dialer.
func (m *Manager) Reset() {
	m.stopAll()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = nil
	m.dialer = nil
	m.listenIP = ""
}

// handleAddTCP handles the TCP add message.
func (m *Manager) handleAddTCP(msg control.Message) error {
	return m.handleAdd(msg, "tcp")
}

// handleRemoveTCP handles the TCP remove message.
func (m *Manager) handleRemoveTCP(msg control.Message) error {
	return m.handleRemove(msg, "tcp")
}

// handleAddUDP handles the UDP add message.
func (m *Manager) handleAddUDP(msg control.Message) error {
	return m.handleAdd(msg, "udp")
}

// handleRemoveUDP handles the UDP remove message.
func (m *Manager) handleRemoveUDP(msg control.Message) error {
	return m.handleRemove(msg, "udp")
}

func (m *Manager) handleAdd(msg control.Message, protocol string) error {
	var data control.TargetsData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal %s add data: %w", protocol, err)
	}

	m.applyTargetStrings(data.Targets, protocol, m.addTarget, "add target failed")
	return nil
}

func (m *Manager) handleRemove(msg control.Message, protocol string) error {
	var data control.TargetsData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal %s remove data: %w", protocol, err)
	}

	m.applyTargetStrings(data.Targets, protocol, func(target Target) error {
		return m.removeTarget(target)
	}, "remove target failed")
	return nil
}

func (m *Manager) applyTargetStrings(targets []string, protocol string, apply func(Target) error, errorMsg string) {
	for _, targetStr := range targets {
		target, err := m.parseTargetString(targetStr, protocol)
		if err != nil {
			m.logger.Warn("invalid target", "protocol", protocol, "target", targetStr, "error", err)
			continue
		}
		if err := apply(target); err != nil {
			m.logger.Warn(errorMsg, "protocol", protocol, "target", targetStr, "error", err)
		}
	}
}

// SyncTargets reconciles the active proxy targets with the desired target set.
func (m *Manager) SyncTargets(targets control.TargetsByType) error {
	// Build set of targets to keep
	keep := make(map[TargetKey]bool)

	m.collectTargetStrings(targets.TCP, "tcp", keep)
	m.collectTargetStrings(targets.UDP, "udp", keep)

	// Remove targets not in sync
	m.mu.Lock()
	pending := m.pending[:0]
	for _, target := range m.pending {
		key := targetKey(target)
		if keep[key] {
			pending = append(pending, target)
		}
	}
	m.pending = pending

	toRemove := make([]TargetKey, 0)
	for key := range m.proxies {
		if !keep[key] {
			toRemove = append(toRemove, key)
		}
	}
	m.mu.Unlock()

	for _, key := range toRemove {
		if err := m.removeTarget(Target{Protocol: key.Protocol, ListenAddr: key.ListenAddr}); err != nil {
			m.logger.Warn("remove stale target failed", "key", key, "error", err)
		}
	}

	return nil
}

func (m *Manager) collectTargetStrings(targets []string, protocol string, keep map[TargetKey]bool) {
	m.applyTargetStrings(targets, protocol, func(target Target) error {
		keep[targetKey(target)] = true
		return m.addTarget(target)
	}, "add target failed")
}

// addTarget adds or updates a proxy target.
func (m *Manager) addTarget(target Target) error {
	processed, err := m.runUpdown("add", target)
	if err != nil {
		m.logger.Warn("updown script error", "action", "add", "protocol", target.Protocol, "target", target.TargetAddr, "error", err)
	} else {
		target = processed
	}

	m.mu.Lock()
	if m.group == nil || m.dialer == nil {
		key := targetKey(target)
		for i, pending := range m.pending {
			if targetKey(pending) == key {
				m.pending[i] = target
				m.mu.Unlock()
				return nil
			}
		}
		m.pending = append(m.pending, target)
		m.mu.Unlock()
		return nil
	}

	key := targetKey(target)
	existing := m.proxies[key]
	if existing != nil {
		delete(m.proxies, key)
	}
	group := m.group
	dialer := m.dialer
	m.mu.Unlock()

	if existing != nil {
		m.logger.Debug("replacing existing proxy", "key", key)
		m.stopProxy(existing)
	}

	_, cancel := context.WithCancel(group.Context())
	stopped := make(chan struct{})

	ap := &activeProxy{
		target:  target,
		cancel:  cancel,
		stopped: stopped,
	}

	switch target.Protocol {
	case "tcp":
		proxy := NewTCPProxy(target, dialer, m.logger)
		ap.tcp = proxy
		group.Go(func(gctx context.Context) error {
			defer close(stopped)
			return proxy.Start(gctx)
		})

	case "udp":
		proxy := NewUDPProxy(target, dialer, m.logger)
		ap.udp = proxy
		group.Go(func(gctx context.Context) error {
			defer close(stopped)
			return proxy.Start(gctx)
		})

	default:
		cancel()
		return fmt.Errorf("unknown protocol: %s", target.Protocol)
	}

	m.mu.Lock()
	m.proxies[key] = ap
	m.mu.Unlock()
	telemetry.AddActiveProxyTargets(target.Protocol, 1)
	m.logger.Info("proxy added",
		"protocol", target.Protocol,
		"listen", target.ListenAddr,
		"target", target.TargetAddr,
	)

	return nil
}

// flushPendingTargets starts any queued targets once the proxy manager is ready.
func (m *Manager) flushPendingTargets() {
	m.mu.Lock()
	if m.group == nil || m.dialer == nil || len(m.pending) == 0 {
		m.mu.Unlock()
		return
	}

	pending := append([]Target(nil), m.pending...)
	m.pending = nil
	m.mu.Unlock()

	for _, target := range pending {
		if err := m.addTarget(target); err != nil {
			m.logger.Warn("flush queued target failed",
				"protocol", target.Protocol,
				"listen", target.ListenAddr,
				"target", target.TargetAddr,
				"error", err,
			)
		}
	}
}

// removeTarget removes a proxy target.
func (m *Manager) removeTarget(target Target) error {
	m.mu.Lock()
	key := targetKey(target)
	proxy := m.proxies[key]
	if proxy != nil {
		delete(m.proxies, key)
		target = proxy.target
	} else {
		for i, pending := range m.pending {
			if targetKey(pending) == key {
				target = pending
				m.pending = append(m.pending[:i], m.pending[i+1:]...)
				break
			}
		}
	}
	m.mu.Unlock()

	if _, err := m.runUpdown("remove", target); err != nil {
		m.logger.Warn("updown script error", "action", "remove", "protocol", target.Protocol, "target", target.TargetAddr, "error", err)
	}

	if proxy == nil {
		return nil
	}

	m.stopProxy(proxy)
	telemetry.AddActiveProxyTargets(target.Protocol, -1)

	m.logger.Info("proxy removed", "protocol", target.Protocol, "listen", target.ListenAddr)
	return nil
}

// stopAll stops all active proxies.
func (m *Manager) stopAll() {
	m.mu.Lock()
	proxies := make([]*activeProxy, 0, len(m.proxies))
	for key, proxy := range m.proxies {
		proxies = append(proxies, proxy)
		delete(m.proxies, key)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, proxy := range proxies {
		wg.Add(1)
		go func(proxy *activeProxy) {
			defer wg.Done()
			telemetry.AddActiveProxyTargets(proxy.target.Protocol, -1)
			m.stopProxy(proxy)
		}(proxy)
	}
	wg.Wait()
}

// Shutdown gracefully shuts down the proxy manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.stopAll()
	return nil
}

// AddTCPTargets adds TCP proxy targets from target strings.
func (m *Manager) AddTCPTargets(targets []string) {
	m.applyTargetStrings(targets, "tcp", m.addTarget, "add target failed")
}

// AddUDPTargets adds UDP proxy targets from target strings.
func (m *Manager) AddUDPTargets(targets []string) {
	m.applyTargetStrings(targets, "udp", m.addTarget, "add target failed")
}

func (m *Manager) stopProxy(proxy *activeProxy) {
	if proxy == nil {
		return
	}
	proxy.cancel()
	<-proxy.stopped
}

func (m *Manager) currentListenIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listenIP
}

func (m *Manager) runUpdown(action string, target Target) (Target, error) {
	if m.updown == "" {
		return target, nil
	}

	parts := strings.Fields(m.updown)
	if len(parts) == 0 {
		return target, fmt.Errorf("invalid updown script command")
	}

	args := append(parts[1:], action, target.Protocol, target.TargetAddr)
	cmd := exec.Command(parts[0], args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return target, fmt.Errorf("updown script execution failed (exit code %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return target, fmt.Errorf("updown script execution failed: %w", err)
	}

	if action != "add" {
		return target, nil
	}

	rewritten := strings.TrimSpace(string(output))
	if rewritten == "" {
		return target, nil
	}
	target.TargetAddr = rewritten
	return target, nil
}

// parseTargetString parses a target string in the format "listenPort:targetHost:targetPort".
// It properly handles IPv6 addresses which must be in brackets: "listenPort:[ipv6]:targetPort"
func (m *Manager) parseTargetString(targetStr, protocol string) (Target, error) {
	// Find the first colon to extract the listen port
	firstColon := strings.Index(targetStr, ":")
	if firstColon == -1 {
		return Target{}, fmt.Errorf("invalid target format: %s (expected port:host:port)", targetStr)
	}

	listenPortStr := targetStr[:firstColon]
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil {
		return Target{}, fmt.Errorf("invalid listen port: %s", listenPortStr)
	}

	// The rest is host:port - handle IPv6 in brackets
	rest := targetStr[firstColon+1:]

	var targetHost, targetPort string
	if strings.HasPrefix(rest, "[") {
		// IPv6 address in brackets: [ipv6]:port
		closeBracket := strings.Index(rest, "]")
		if closeBracket == -1 {
			return Target{}, fmt.Errorf("invalid IPv6 format: %s", targetStr)
		}
		targetHost = rest[:closeBracket+1] // Include brackets
		if len(rest) <= closeBracket+2 || rest[closeBracket+1] != ':' {
			return Target{}, fmt.Errorf("invalid target format: %s", targetStr)
		}
		targetPort = rest[closeBracket+2:]
	} else {
		// IPv4 or hostname: host:port
		lastColon := strings.LastIndex(rest, ":")
		if lastColon == -1 {
			return Target{}, fmt.Errorf("invalid target format: %s (expected port:host:port)", targetStr)
		}
		targetHost = rest[:lastColon]
		targetPort = rest[lastColon+1:]
	}

	listenIP := m.currentListenIP()
	if listenIP == "" {
		return Target{}, errors.New("no tunnel listen ip set")
	}

	return Target{
		Protocol:   protocol,
		ListenAddr: fmt.Sprintf("%s:%d", listenIP, listenPort),
		TargetAddr: fmt.Sprintf("%s:%s", targetHost, targetPort),
		Enabled:    true,
	}, nil
}
