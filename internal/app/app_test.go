package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/clients"
	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/health"
	"github.com/fosrl/newt/internal/lifecycle"
	"github.com/fosrl/newt/internal/proxy"
	"github.com/fosrl/newt/internal/tunnel"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTunnelLifecycleSeedsAndClearsManagers(t *testing.T) {
	a := &App{
		logger: testLogger(),
		proxy:  proxy.NewManager(nil, testLogger()),
		health: health.NewMonitor(nil, false, testLogger()),
	}

	info := tunnel.TunnelInfo{
		LocalAddr:         netip.MustParseAddr("100.64.0.10"),
		PeerKey:           "peer-key",
		PeerEndpoint:      "198.51.100.20:51820",
		RelayPort:         21820,
		InitialTCPTargets: []string{"8080:127.0.0.1:8080"},
		InitialUDPTargets: []string{"5353:127.0.0.1:5353"},
		InitialHealthChecks: []tunnel.HealthCheckInfo{
			{
				TargetID:          1,
				Hostname:          "127.0.0.1",
				Port:              8080,
				Path:              "/health",
				Scheme:            "http",
				Mode:              "tcp",
				Method:            "GET",
				ExpectedStatus:    200,
				Interval:          30,
				UnhealthyInterval: 10,
				Timeout:           5,
				Enabled:           true,
			},
		},
	}

	a.handleTunnelConnectWithNetstack(info, &tunnel.NetStack{})

	if got := a.proxy.ListenIP(); got != "100.64.0.10" {
		t.Fatalf("expected proxy listen IP to be seeded, got %q", got)
	}
	if got := a.proxy.PendingCount(); got != 2 {
		t.Fatalf("expected 2 pending proxy targets, got %d", got)
	}
	if got := a.health.TargetCount(); got != 1 {
		t.Fatalf("expected 1 health target, got %d", got)
	}

	a.handleTunnelDisconnect()

	if got := a.proxy.ListenIP(); got != "" {
		t.Fatalf("expected proxy listen IP to be cleared, got %q", got)
	}
	if got := a.proxy.PendingCount(); got != 0 {
		t.Fatalf("expected pending proxy targets to be cleared, got %d", got)
	}
	if got := a.health.TargetCount(); got != 0 {
		t.Fatalf("expected health targets to be cleared, got %d", got)
	}
}

func TestHandleControlConnectRequestsPingClientsAndBlueprint(t *testing.T) {
	var (
		pingCalled          bool
		pingNoCloud         bool
		registerCalled      bool
		registerPayload     control.WgRegisterData
		blueprintCalled     bool
		clientConfigCalled  bool
		clientTokenWasSet   bool
		clientTokenObserved string
		messageTypes        []string
	)

	a := &App{
		cfg:    &Config{NoCloud: true},
		logger: testLogger(),
		tunnel: tunnel.NewManager(tunnel.Config{}, nil, testLogger()),
		clients: &clients.Manager{},
		sendControlData: func(ctx context.Context, msgType string, data any) error {
			messageTypes = append(messageTypes, msgType)
			switch msgType {
			case control.MsgPingRequest:
				req, ok := data.(control.PingRequestData)
				if !ok {
					t.Fatalf("unexpected ping request payload type: %T", data)
				}
				pingCalled = true
				pingNoCloud = req.NoCloud
			case control.MsgWgRegister:
				req, ok := data.(control.WgRegisterData)
				if !ok {
					t.Fatalf("unexpected register payload type: %T", data)
				}
				registerCalled = true
				registerPayload = req
			default:
				t.Fatalf("unexpected control message type: %s", msgType)
			}
			return nil
		},
		sendBlueprintFunc: func() error {
			blueprintCalled = true
			return nil
		},
		setClientsTokenFunc: func(token string) {
			clientTokenWasSet = true
			clientTokenObserved = token
		},
		requestClientsConfigFn: func(ctx context.Context) error {
			clientConfigCalled = true
			return nil
		},
		control: control.NewClient(control.ClientConfig{}, testLogger()),
	}

	a.handleControlConnect()

	if !pingCalled {
		t.Fatal("expected ping request to be sent")
	}
	if !pingNoCloud {
		t.Fatal("expected ping request to honor NoCloud")
	}
	if !registerCalled {
		t.Fatal("expected compatibility registration to be sent")
	}
	if registerPayload.BackwardsCompatible != true {
		t.Fatal("expected compatibility registration flag to be set")
	}
	if len(messageTypes) < 2 || messageTypes[0] != control.MsgPingRequest || messageTypes[1] != control.MsgWgRegister {
		t.Fatalf("unexpected control message order: %v", messageTypes)
	}
	if !clientTokenWasSet {
		t.Fatal("expected client token to be set")
	}
	if clientTokenObserved != "" {
		t.Fatalf("expected empty token in this unit test setup, got %q", clientTokenObserved)
	}
	if !clientConfigCalled {
		t.Fatal("expected client config request to be triggered")
	}
	if !blueprintCalled {
		t.Fatal("expected blueprint send to be attempted")
	}
}

func TestHandleControlReconnectSkipsExitNodeRequestWhenTunnelConnected(t *testing.T) {
	var (
		messageTypes       []string
		clientConfigCalled bool
		blueprintCalled    bool
	)

	a := &App{
		cfg:    &Config{NoCloud: true},
		logger: testLogger(),
		tunnel: tunnel.NewManager(tunnel.Config{}, nil, testLogger()),
		clients: &clients.Manager{},
		tunnelStateFn: func() tunnel.TunnelState {
			return tunnel.StateConnected
		},
		sendControlData: func(ctx context.Context, msgType string, data any) error {
			messageTypes = append(messageTypes, msgType)
			return nil
		},
		sendBlueprintFunc: func() error {
			blueprintCalled = true
			return nil
		},
		requestClientsConfigFn: func(ctx context.Context) error {
			clientConfigCalled = true
			return nil
		},
		control: control.NewClient(control.ClientConfig{}, testLogger()),
	}

	a.handleControlConnect()

	if len(messageTypes) == 0 {
		t.Fatal("expected at least one control message")
	}
	if messageTypes[0] == control.MsgPingRequest {
		t.Fatalf("expected reconnect path to skip ping request, got %v", messageTypes)
	}
	if messageTypes[0] != control.MsgWgRegister {
		t.Fatalf("expected first reconnect message to be register, got %v", messageTypes)
	}
	if !clientConfigCalled {
		t.Fatal("expected client config request on reconnect")
	}
	if !blueprintCalled {
		t.Fatal("expected blueprint send on reconnect")
	}
}

func TestRegisterRetryStartsAndStopsOnTunnelConnect(t *testing.T) {
	var (
		mu        sync.Mutex
		registers int
	)

	a := &App{
		logger:             testLogger(),
		registerRetryEvery: time.Millisecond,
		sendControlData: func(ctx context.Context, msgType string, data any) error {
			if msgType == control.MsgWgRegister {
				mu.Lock()
				registers++
				mu.Unlock()
			}
			return nil
		},
		proxy:  proxy.NewManager(nil, testLogger()),
		health: health.NewMonitor(nil, false, testLogger()),
	}

	a.startRegisterRetry(map[string]any{
		"publicKey": "pubkey",
	})

	time.Sleep(5 * time.Millisecond)

	mu.Lock()
	beforeConnect := registers
	mu.Unlock()
	if beforeConnect < 2 {
		t.Fatalf("expected repeated registrations before connect, got %d", beforeConnect)
	}

	a.handleTunnelConnectWithNetstack(tunnel.TunnelInfo{
		LocalAddr: netip.MustParseAddr("100.64.0.10"),
	}, &tunnel.NetStack{})

	time.Sleep(5 * time.Millisecond)

	mu.Lock()
	afterConnect := registers
	mu.Unlock()
	if afterConnect != beforeConnect {
		t.Fatalf("expected registration retry to stop after connect, before=%d after=%d", beforeConnect, afterConnect)
	}
}

func TestHandleControlDisconnectStopsRetryWithoutTearingDownDataPlane(t *testing.T) {
	var (
		mu        sync.Mutex
		registers int
	)

	a := &App{
		logger:             testLogger(),
		registerRetryEvery: time.Millisecond,
		sendControlData: func(ctx context.Context, msgType string, data any) error {
			if msgType == control.MsgWgRegister {
				mu.Lock()
				registers++
				mu.Unlock()
			}
			return nil
		},
		proxy:  proxy.NewManager(nil, testLogger()),
		health: health.NewMonitor(nil, false, testLogger()),
	}

	a.handleTunnelConnectWithNetstack(tunnel.TunnelInfo{
		LocalAddr:         netip.MustParseAddr("100.64.0.10"),
		InitialTCPTargets: []string{"8080:127.0.0.1:8080"},
		InitialHealthChecks: []tunnel.HealthCheckInfo{{
			TargetID:  1,
			Hostname:  "127.0.0.1",
			Port:      8080,
			Scheme:    "http",
			Mode:      "http",
			Method:    "GET",
			Enabled:   true,
		}},
	}, &tunnel.NetStack{})

	a.startRegisterRetry(map[string]any{"publicKey": "pubkey"})
	time.Sleep(5 * time.Millisecond)
	a.handleControlDisconnect(errors.New("unexpected EOF"))
	time.Sleep(5 * time.Millisecond)

	mu.Lock()
	countAfterDisconnect := registers
	mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	mu.Lock()
	countLater := registers
	mu.Unlock()

	if countLater != countAfterDisconnect {
		t.Fatalf("expected register retry to stop on control disconnect, before=%d after=%d", countAfterDisconnect, countLater)
	}
	if got := a.proxy.ListenIP(); got != "100.64.0.10" {
		t.Fatalf("expected proxy listen IP to remain seeded, got %q", got)
	}
	if got := a.health.TargetCount(); got != 1 {
		t.Fatalf("expected health targets to remain active, got %d", got)
	}
}

func TestShutdownSendsDisconnectingMessage(t *testing.T) {
	var (
		msgType string
		payload []byte
	)

	a := &App{
		logger:     testLogger(),
		supervisor: lifecycle.NewSupervisor(testLogger()),
		sendControlData: func(ctx context.Context, gotType string, data any) error {
			msgType = gotType
			raw, err := json.Marshal(data)
			if err != nil {
				t.Fatalf("marshal shutdown payload: %v", err)
			}
			payload = raw
			return nil
		},
	}

	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}

	if msgType != control.MsgDisconnecting {
		t.Fatalf("expected %q, got %q", control.MsgDisconnecting, msgType)
	}
	if string(payload) != "{}" {
		t.Fatalf("expected empty object payload, got %s", payload)
	}
}

func TestBuildInitialHealthChecks(t *testing.T) {
	checks := buildInitialHealthChecks([]tunnel.HealthCheckInfo{{
		TargetID:          7,
		Hostname:          "127.0.0.1",
		Port:              8080,
		Path:              "/ready",
		Scheme:            "http",
		Mode:              "tcp",
		Method:            "GET",
		ExpectedStatus:    204,
		Headers:           map[string]string{"Host": "example.test"},
		Interval:          30,
		UnhealthyInterval: 10,
		Timeout:           5,
		TLSServerName:     "example.test",
		Enabled:           true,
	}})

	if len(checks) != 1 {
		t.Fatalf("expected 1 health check, got %d", len(checks))
	}
	got := checks[0]
	if got.ID != 7 || got.Mode != "tcp" || got.Status != 204 || got.TLSServerName != "example.test" {
		t.Fatalf("unexpected converted health check: %#v", got)
	}
}

func TestHandleControlConnectWithoutControlSenderDoesNotPanic(t *testing.T) {
	a := &App{
		cfg:    &Config{},
		logger: testLogger(),
		tunnel: &tunnel.Manager{},
	}

	a.handleControlConnect()
}
