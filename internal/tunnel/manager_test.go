package tunnel

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/control"
	pkglogger "github.com/fosrl/newt/pkg/logger"
)

func TestInfoReturnsActiveTunnelMetadata(t *testing.T) {
	m := &Manager{}
	m.state.Store(int32(StateConnected))
	m.tunnel.Store(&activeTunnel{
		peerKey:      "peer-key",
		peerEndpoint: "198.51.100.10:51820",
		relayPort:    21820,
		localIP:      netip.MustParseAddr("100.64.0.10"),
	})

	info, err := m.Info()
	if err != nil {
		t.Fatalf("info returned error: %v", err)
	}

	if info.State != StateConnected {
		t.Fatalf("expected connected state, got %v", info.State)
	}
	if info.PeerKey != "peer-key" {
		t.Fatalf("expected peer key to round-trip, got %q", info.PeerKey)
	}
	if info.PeerEndpoint != "198.51.100.10:51820" {
		t.Fatalf("expected peer endpoint to round-trip, got %q", info.PeerEndpoint)
	}
	if info.RelayPort != 21820 {
		t.Fatalf("expected relay port 21820, got %d", info.RelayPort)
	}
	if info.LocalAddr != netip.MustParseAddr("100.64.0.10") {
		t.Fatalf("unexpected local addr: %s", info.LocalAddr)
	}
}

func TestInfoWithoutTunnelReturnsCurrentState(t *testing.T) {
	m := &Manager{}
	m.state.Store(int32(StateReconnecting))

	info, err := m.Info()
	if err != nil {
		t.Fatalf("info returned error: %v", err)
	}

	if info.State != StateReconnecting {
		t.Fatalf("expected reconnecting state, got %v", info.State)
	}
	if info.PeerEndpoint != "" {
		t.Fatalf("expected empty peer endpoint without active tunnel, got %q", info.PeerEndpoint)
	}
}

func TestRequestRecoverySendsOneRegisterAndRepeatedPingRequests(t *testing.T) {
	m := &Manager{
		control:       control.NewClient(control.ClientConfig{}, nil),
		logger:        pkglogger.Discard(),
		recoveryEvery: 10 * time.Millisecond,
	}
	m.state.Store(int32(StateConnected))

	var (
		mu       sync.Mutex
		messages []string
	)
	m.sendControlData = func(ctx context.Context, msgType string, data any) error {
		mu.Lock()
		messages = append(messages, msgType)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.ctx = ctx

	m.requestRecovery("test")
	time.Sleep(35 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	registerCount := 0
	pingCount := 0
	for _, msg := range messages {
		switch msg {
		case control.MsgWgRegister:
			registerCount++
		case control.MsgPingRequest:
			pingCount++
		}
	}

	if registerCount != 1 {
		t.Fatalf("expected exactly one recovery register, got %d (%v)", registerCount, messages)
	}
	if pingCount < 2 {
		t.Fatalf("expected repeated ping requests, got %d (%v)", pingCount, messages)
	}
	if len(messages) < 2 || messages[0] != control.MsgWgRegister || messages[1] != control.MsgPingRequest {
		t.Fatalf("unexpected message order: %v", messages)
	}
}

func TestHandleConnectKeepsExistingTunnelForIdenticalConfig(t *testing.T) {
	logger := pkglogger.Discard()
	data := control.WgConnectData{
		Endpoint:  "198.51.100.10:51820",
		RelayPort: 21820,
		ServerIP:  "100.89.128.1",
		PublicKey: "peer-key",
		TunnelIP:  "100.89.128.10",
		Targets: control.TargetsByType{
			TCP: []string{"80:127.0.0.1:80"},
		},
		HealthCheckTargets: []control.HealthCheckData{{
			ID:       1,
			Hostname: "127.0.0.1",
			Port:     80,
		}},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal connect data: %v", err)
	}

	existing := &activeTunnel{
		device:      &Device{},
		connectData: data,
	}

	m := &Manager{
		logger: logger,
	}
	m.tunnel.Store(existing)
	m.state.Store(int32(StateConnected))

	if err := m.handleConnect(control.Message{Type: control.MsgWgConnect, Data: raw}); err != nil {
		t.Fatalf("handle connect: %v", err)
	}

	if got := m.tunnel.Load(); got != existing {
		t.Fatal("expected identical connect to keep existing tunnel")
	}
	if got := m.State(); got != StateConnected {
		t.Fatalf("expected connected state, got %v", got)
	}
}
