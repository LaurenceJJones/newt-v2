package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/internal/authdaemon"
	"github.com/fosrl/newt/internal/clients"
	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/docker"
	"github.com/fosrl/newt/internal/expose"
	"github.com/fosrl/newt/internal/health"
	"github.com/fosrl/newt/internal/lifecycle"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/internal/tunnel"
	"github.com/fosrl/newt/pkg/version"
	"go.yaml.in/yaml/v2"
)

// App is the main application orchestrator that coordinates all components.
type App struct {
	cfg        *Config
	logger     *slog.Logger
	supervisor *lifecycle.Supervisor

	// Components
	telemetry *telemetry.Provider
	control   *control.Client
	tunnel    *tunnel.Manager
	proxy     *expose.Manager
	health    *health.Monitor
	docker    *docker.Discovery
	clients   *clients.Manager
	auth      *authdaemon.Server

	registerMu          sync.Mutex
	registerRetryCancel context.CancelFunc
	registerRetryEvery  time.Duration

	// Test seams for orchestration methods.
	sendControlData        func(ctx context.Context, msgType string, data any) error
	sendBlueprintFunc      func() error
	setClientsTokenFunc    func(token string)
	requestClientsConfigFn func(ctx context.Context) error
	tunnelStateFn          func() tunnel.TunnelState
}

func (a *App) controlSender() func(ctx context.Context, msgType string, data any) error {
	if a.sendControlData != nil {
		return a.sendControlData
	}
	if a.control != nil {
		return a.control.SendData
	}
	return nil
}

func (a *App) blueprintSender() func() error {
	if a.sendBlueprintFunc != nil {
		return a.sendBlueprintFunc
	}
	return a.sendBlueprint
}

func (a *App) setClientsToken(token string) {
	if a.clients == nil {
		return
	}
	if a.setClientsTokenFunc != nil {
		a.setClientsTokenFunc(token)
		return
	}
	a.clients.SetToken(token)
}

func (a *App) requestClientsConfig(ctx context.Context) error {
	if a.clients == nil {
		return nil
	}
	if a.requestClientsConfigFn != nil {
		return a.requestClientsConfigFn(ctx)
	}
	return a.clients.RequestConfig(ctx)
}

func (a *App) currentTunnelState() tunnel.TunnelState {
	if a.tunnelStateFn != nil {
		return a.tunnelStateFn()
	}
	if a.tunnel == nil {
		return tunnel.StateDisconnected
	}
	return a.tunnel.State()
}

func (a *App) configureTunnelNetstack(info tunnel.TunnelInfo, ns *tunnel.NetStack) {
	a.proxy.SetListenIP(info.LocalAddr.String())
	a.proxy.SetDialer(&netstackDialer{ns: ns})
	if a.clients == nil {
		return
	}

	a.clients.SetMainNetstack(ns)
	if err := a.clients.StartHolepunch(info.PeerKey, info.PeerEndpoint, info.RelayPort); err != nil {
		a.logger.Warn("failed to start clients hole punch", "error", err)
	}
	if err := a.clients.StartDirectRelay(info.LocalAddr.String()); err != nil {
		a.logger.Warn("failed to start clients direct relay", "error", err)
	}
}

func (a *App) applyInitialTunnelTargets(info tunnel.TunnelInfo) {
	if len(info.InitialTCPTargets) > 0 {
		a.proxy.AddTCPTargets(info.InitialTCPTargets)
	}
	if len(info.InitialUDPTargets) > 0 {
		a.proxy.AddUDPTargets(info.InitialUDPTargets)
	}
	if len(info.InitialHealthChecks) == 0 {
		return
	}

	healthChecks := buildInitialHealthChecks(info.InitialHealthChecks)
	if err := a.health.AddTargets(healthChecks); err != nil {
		a.logger.Warn("failed to add initial health checks", "error", err)
	}
}

func (a *App) registerTunnelWithControl(sendControlData func(ctx context.Context, msgType string, data any) error, shouldRequestExitNodes bool) {
	if shouldRequestExitNodes {
		a.logger.Debug("requesting exit nodes", "public_key", a.tunnel.PublicKey())
		if err := sendControlData(context.Background(), control.MsgPingRequest, control.PingRequestData{
			NoCloud: a.cfg.NoCloud,
		}); err != nil {
			a.logger.Error("failed to send ping request", "error", err)
		}
	}

	if err := sendControlData(context.Background(), control.MsgWgRegister, control.WgRegisterData{
		PublicKey:           a.tunnel.PublicKey(),
		NewtVersion:         version.Short(),
		BackwardsCompatible: true,
	}); err != nil {
		a.logger.Error("failed to send initial registration", "error", err)
	}
}

func (a *App) refreshControlManagedState() {
	if a.clients != nil {
		a.setClientsToken(a.control.Token())
		if err := a.requestClientsConfig(context.Background()); err != nil {
			a.logger.Warn("failed to request client WG config", "error", err)
		}
	}

	if err := a.blueprintSender()(); err != nil {
		a.logger.Error("failed to send blueprint", "error", err)
	}
}

func (a *App) handleExitNodes(msg control.Message) error {
	var data control.ExitNodesData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal exit nodes: %w", err)
	}

	a.logger.Debug("received exit nodes", "count", len(data.ExitNodes))
	if len(data.ExitNodes) == 0 {
		a.logger.Warn("no exit nodes provided")
		return nil
	}

	pingResults := a.pingExitNodes(data.ExitNodes)
	a.logger.Debug("registering with ping results", "public_key", a.tunnel.PublicKey())
	payload := map[string]any{
		"publicKey":   a.tunnel.PublicKey(),
		"pingResults": pingResults,
		"newtVersion": version.Short(),
	}
	a.startRegisterRetry(payload)
	return nil
}

func (a *App) handleSync(msg control.Message) error {
	var data control.SyncData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal sync data: %w", err)
	}

	if err := a.proxy.SyncTargets(data.Targets); err != nil {
		return fmt.Errorf("sync proxy targets: %w", err)
	}
	if err := a.health.SyncTargets(data.HealthCheckTargets); err != nil {
		return fmt.Errorf("sync health checks: %w", err)
	}

	a.logger.Debug("sync applied",
		"tcp_targets", len(data.Targets.TCP),
		"udp_targets", len(data.Targets.UDP),
		"health_checks", len(data.HealthCheckTargets),
	)
	return nil
}

func (a *App) handleBlueprintResults(msg control.Message) error {
	var result control.BlueprintResultData
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return fmt.Errorf("unmarshal blueprint result: %w", err)
	}

	if result.Success {
		a.logger.Info("blueprint applied successfully")
		return nil
	}

	a.logger.Warn("blueprint application failed", "message", result.Message)
	return nil
}

func (a *App) sendRegisterPayload(sendControlData func(ctx context.Context, msgType string, data any) error, payload any) error {
	return sendControlData(context.Background(), control.MsgWgRegister, payload)
}

func (a *App) replaceRegisterRetry(cancel context.CancelFunc) {
	a.registerMu.Lock()
	defer a.registerMu.Unlock()

	if a.registerRetryCancel != nil {
		a.registerRetryCancel()
	}
	a.registerRetryCancel = cancel
}

func (a *App) runRegisterRetry(ctx context.Context, sendControlData func(ctx context.Context, msgType string, data any) error, payload any) {
	ticker := time.NewTicker(a.registerRetryEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendRegisterPayload(sendControlData, payload); err != nil {
				a.logger.Warn("failed to retry registration with ping results", "error", err)
			}
		}
	}
}

func buildInitialHealthChecks(checks []tunnel.HealthCheckInfo) []control.HealthCheckData {
	if len(checks) == 0 {
		return nil
	}
	healthChecks := make([]control.HealthCheckData, len(checks))
	for i, hc := range checks {
		healthChecks[i] = control.HealthCheckData{
			ID:                hc.TargetID,
			Mode:              hc.Mode,
			Hostname:          hc.Hostname,
			Port:              hc.Port,
			Path:              hc.Path,
			Scheme:            hc.Scheme,
			Method:            hc.Method,
			Status:            hc.ExpectedStatus,
			Headers:           hc.Headers,
			Interval:          hc.Interval,
			UnhealthyInterval: hc.UnhealthyInterval,
			Timeout:           hc.Timeout,
			TLSServerName:     hc.TLSServerName,
			Enabled:           hc.Enabled,
		}
	}
	return healthChecks
}

func (a *App) initTelemetry() error {
	if !a.cfg.MetricsEnabled && !a.cfg.OTLPEnabled {
		return nil
	}

	provider, err := telemetry.NewProvider(telemetry.Config{
		ServiceName:    "newt",
		ServiceVersion: version.Short(),
		Region:         a.cfg.Region,
		PrometheusAddr: a.cfg.AdminAddr,
		PprofEnabled:   a.cfg.PprofEnabled,
		OTLPEnabled:    a.cfg.OTLPEnabled,
	}, a.logger)
	if err != nil {
		return fmt.Errorf("create telemetry: %w", err)
	}
	a.telemetry = provider
	a.supervisor.Add(a.telemetry)
	return nil
}

func (a *App) buildTLSConfig() (*tls.Config, error) {
	if a.cfg.TLSClientCert == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(a.cfg.TLSClientCert, a.cfg.TLSClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func (a *App) initControlAndTunnel(tlsConfig *tls.Config) error {
	controlCfg := control.DefaultClientConfig()
	controlCfg.Endpoint = a.cfg.Endpoint
	controlCfg.ID = a.cfg.ID
	controlCfg.Secret = a.cfg.Secret
	controlCfg.TLSConfig = tlsConfig

	a.control = control.NewClient(controlCfg, a.logger)

	tunnelCfg := tunnel.Config{
		InterfaceName: a.cfg.InterfaceName,
		MTU:           a.cfg.MTU,
		DNS:           a.cfg.DNS,
		LocalPort:     a.cfg.Port,
		NativeMode:    a.cfg.NativeMode,
		PingInterval:  time.Duration(a.cfg.PingInterval) * time.Second,
		PingTimeout:   time.Duration(a.cfg.PingTimeout) * time.Second,
		NoCloud:       a.cfg.NoCloud,
	}
	a.tunnel = tunnel.NewManager(tunnelCfg, a.control, a.logger)

	if a.cfg.DisableClients {
		return nil
	}

	clientsManager, err := clients.NewManager(a.cfg.Port, a.cfg.MTU, a.cfg.DNS, a.control, a.logger)
	if err != nil {
		return fmt.Errorf("create clients manager: %w", err)
	}
	a.clients = clientsManager
	return nil
}

func (a *App) wireControlAndTunnel() {
	a.tunnel.OnConnect(a.handleTunnelConnect)
	a.tunnel.OnDisconnect(a.handleTunnelDisconnect)

	a.control.OnConnect(a.handleControlConnect)
	a.control.OnDisconnect(a.handleControlDisconnect)

	a.control.Register(control.MsgPingExitNodes, a.handleExitNodes)
	a.control.Register(control.MsgSync, a.handleSync)
	a.control.Register(control.MsgBlueprintResults, a.handleBlueprintResults)

	a.supervisor.Add(a.control)
	a.supervisor.Add(a.tunnel)
}

func (a *App) initManagedServices() error {
	a.proxy = expose.NewManager(a.control, a.logger)
	a.supervisor.Add(a.proxy)

	a.health = health.NewMonitor(a.control, a.cfg.EnforceHealthCert, a.logger)
	a.supervisor.Add(a.health)

	a.docker = docker.NewDiscovery(a.cfg.DockerSocket, "", a.cfg.DockerEnforceNetworkValidation, a.control, a.logger)
	a.supervisor.Add(a.docker)

	if a.cfg.AuthDaemonEnabled {
		authCfg := authdaemon.Config{
			DisableHTTPS:           a.cfg.AuthDaemonAddr == "",
			ListenAddr:             a.cfg.AuthDaemonAddr,
			PreSharedKey:           a.cfg.AuthDaemonKey,
			CACertPath:             a.cfg.AuthDaemonCAPath,
			HostCAPath:             a.cfg.AuthDaemonHostCAPath,
			PrincipalsFilePath:     a.cfg.AuthDaemonPrincipals,
			Force:                  true,
			GenerateRandomPassword: a.cfg.AuthDaemonRandomPass,
		}
		server, err := authdaemon.NewServer(authCfg, a.control, a.logger)
		if err != nil {
			return fmt.Errorf("create auth daemon: %w", err)
		}
		a.auth = server
		a.supervisor.Add(a.auth)
	}

	if a.clients != nil {
		a.supervisor.Add(a.clients)
	}
	return nil
}

// New creates a new App instance with the given configuration.
func New(cfg *Config, logger *slog.Logger) (*App, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	app := &App{
		cfg:                cfg,
		logger:             logger,
		supervisor:         lifecycle.NewSupervisor(logger),
		registerRetryEvery: 2 * time.Second,
	}

	if err := app.initComponents(); err != nil {
		return nil, fmt.Errorf("init components: %w", err)
	}

	return app, nil
}

// initComponents initializes all application components.
func (a *App) initComponents() error {
	if err := a.initTelemetry(); err != nil {
		return err
	}

	tlsConfig, err := a.buildTLSConfig()
	if err != nil {
		return err
	}
	if err := a.initControlAndTunnel(tlsConfig); err != nil {
		return err
	}

	a.wireControlAndTunnel()

	if err := a.initManagedServices(); err != nil {
		return err
	}

	a.logger.Info("components initialized",
		"endpoint", a.cfg.Endpoint,
		"id", a.cfg.ID,
		"metrics", a.cfg.MetricsEnabled,
	)

	return nil
}

// Run starts all components and blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	a.logger.Info("starting newt",
		"version", version.Short(),
		"endpoint", a.cfg.Endpoint,
		"mtu", a.cfg.MTU,
		"dns", a.cfg.DNS,
	)

	return a.supervisor.Run(ctx)
}

func (a *App) handleTunnelConnect(info tunnel.TunnelInfo) {
	var ns *tunnel.NetStack
	if a.tunnel != nil {
		ns = a.tunnel.NetStack()
	}
	a.handleTunnelConnectWithNetstack(info, ns)
}

func (a *App) handleTunnelConnectWithNetstack(info tunnel.TunnelInfo, ns *tunnel.NetStack) {
	a.stopRegisterRetry()
	a.logger.Info("tunnel connected",
		"local_ip", info.LocalAddr,
		"peer", info.PeerKey,
		"tcp_targets", len(info.InitialTCPTargets),
		"udp_targets", len(info.InitialUDPTargets),
		"health_checks", len(info.InitialHealthChecks),
	)

	if ns != nil {
		a.configureTunnelNetstack(info, ns)
	}
	a.applyInitialTunnelTargets(info)
}

func (a *App) handleTunnelDisconnect() {
	a.stopRegisterRetry()
	a.proxy.Reset()
	a.health.Reset()
	if a.clients != nil {
		a.clients.Reset()
	}
	a.logger.Info("tunnel disconnected")
}

func (a *App) handleControlConnect() {
	a.stopRegisterRetry()
	sendControlData := a.controlSender()
	if sendControlData == nil {
		a.logger.Warn("control sender unavailable on connect")
		return
	}

	shouldRequestExitNodes := a.currentTunnelState() != tunnel.StateConnected
	a.registerTunnelWithControl(sendControlData, shouldRequestExitNodes)
	a.refreshControlManagedState()
}

func (a *App) handleControlDisconnect(err error) {
	a.stopRegisterRetry()
	a.logger.Warn("control plane disconnected; keeping data plane running", "error", err)
}

func (a *App) startRegisterRetry(payload any) {
	sendControlData := a.controlSender()
	if sendControlData == nil {
		a.logger.Warn("control sender unavailable for register retry")
		return
	}

	a.stopRegisterRetry()

	if err := a.sendRegisterPayload(sendControlData, payload); err != nil {
		a.logger.Error("failed to send registration with ping results", "error", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.replaceRegisterRetry(cancel)
	go a.runRegisterRetry(ctx, sendControlData, payload)
}

func (a *App) stopRegisterRetry() {
	a.registerMu.Lock()
	cancel := a.registerRetryCancel
	a.registerRetryCancel = nil
	a.registerMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// pingExitNodes pings each exit node and returns results.
func (a *App) pingExitNodes(nodes []control.ExitNode) []control.ExitNodePingResult {
	results := make([]control.ExitNodePingResult, len(nodes))
	client := &http.Client{Timeout: 5 * time.Second}

	for i, node := range nodes {
		result := control.ExitNodePingResult{
			ExitNodeID:             node.ID,
			Weight:                 node.Weight,
			Name:                   node.Name,
			Endpoint:               node.Endpoint,
			WasPreviouslyConnected: node.WasPreviouslyConnected,
		}

		// Build ping URL
		url := node.Endpoint
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		if !strings.HasSuffix(url, "/ping") {
			url = strings.TrimRight(url, "/") + "/ping"
		}

		// Ping 3 times and average
		const attempts = 3
		var totalLatency time.Duration
		var successes int

		for j := 0; j < attempts; j++ {
			start := time.Now()
			resp, err := client.Get(url)
			latency := time.Since(start)

			if err != nil {
				a.logger.Debug("ping failed", "node", node.Name, "attempt", j+1, "error", err)
				result.Error = err.Error()
				continue
			}
			_ = resp.Body.Close()

			totalLatency += latency
			successes++
		}

		if successes > 0 {
			avgLatency := totalLatency / time.Duration(successes)
			result.LatencyMs = avgLatency.Milliseconds()
			result.Error = ""
		} else {
			result.LatencyMs = -1
		}

		results[i] = result
		a.logger.Debug("pinged exit node", "node", node.Name, "latency_ms", result.LatencyMs)
	}

	return results
}

func (a *App) sendBlueprint() error {
	if a.cfg.BlueprintFile == "" {
		return nil
	}

	data, err := os.ReadFile(a.cfg.BlueprintFile)
	if err != nil {
		return fmt.Errorf("read blueprint file: %w", err)
	}

	var blueprint any
	if err := yaml.Unmarshal(data, &blueprint); err != nil {
		return fmt.Errorf("parse blueprint yaml: %w", err)
	}

	jsonData, err := json.Marshal(blueprint)
	if err != nil {
		return fmt.Errorf("marshal blueprint json: %w", err)
	}

	return a.control.SendData(context.Background(), control.MsgBlueprintApply, control.BlueprintApplyData{
		Blueprint: string(jsonData),
	})
}

// Shutdown gracefully stops all components.
func (a *App) Shutdown(ctx context.Context) error {
	a.logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sendControlData := a.sendControlData
	if sendControlData == nil {
		sendControlData = a.controlSender()
	}
	if sendControlData != nil {
		if err := sendControlData(shutdownCtx, control.MsgDisconnecting, struct{}{}); err != nil {
			a.logger.Debug("failed to send disconnecting message", "error", err)
		}
	}

	return a.supervisor.Shutdown(shutdownCtx)
}

// Config returns the application configuration.
func (a *App) Config() *Config {
	return a.cfg
}

// netstackDialer adapts tunnel.NetStack to proxy.NetDialer interface.
type netstackDialer struct {
	ns *tunnel.NetStack
}

func (d *netstackDialer) DialTCP(addr string) (net.Conn, error) {
	return d.ns.DialTCP(context.Background(), addr)
}

func (d *netstackDialer) DialUDP(laddr, raddr string) (net.Conn, error) {
	return d.ns.DialUDP(context.Background(), laddr, raddr)
}

func (d *netstackDialer) ListenTCP(addr string) (net.Listener, error) {
	return d.ns.ListenTCP(addr)
}

func (d *netstackDialer) ListenUDP(addr string) (net.PacketConn, error) {
	return d.ns.ListenUDP(addr)
}
