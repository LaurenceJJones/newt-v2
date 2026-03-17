package holepunch

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSyncExitNodesReplacesExistingNodes(t *testing.T) {
	m := NewManager("newt-id", "newt", "public-key", testLogger())

	err := m.SyncExitNodes([]ExitNode{
		{ID: "one", Endpoint: "127.0.0.1", RelayPort: 21820, PublicKey: "pk1"},
	})
	if err != nil {
		t.Fatalf("sync exit nodes: %v", err)
	}

	err = m.SyncExitNodes([]ExitNode{
		{ID: "two", Endpoint: "127.0.0.2", RelayPort: 30000, PublicKey: "pk2"},
	})
	if err != nil {
		t.Fatalf("replace exit nodes: %v", err)
	}

	if _, ok := m.nodes["one"]; ok {
		t.Fatal("expected old exit node to be removed")
	}
	if _, ok := m.nodes["two"]; !ok {
		t.Fatal("expected new exit node to be present")
	}
}

func TestSyncExitNodesAllowsClearingNodes(t *testing.T) {
	m := NewManager("newt-id", "newt", "public-key", testLogger())

	err := m.SyncExitNodes([]ExitNode{
		{ID: "one", Endpoint: "127.0.0.1", RelayPort: 21820, PublicKey: "pk1"},
	})
	if err != nil {
		t.Fatalf("sync exit nodes: %v", err)
	}

	err = m.SyncExitNodes(nil)
	if err != nil {
		t.Fatalf("clear exit nodes: %v", err)
	}

	if len(m.nodes) != 0 {
		t.Fatalf("expected no exit nodes, got %d", len(m.nodes))
	}
}

func TestResolveExitNodeAddrUsesRelayPortDefault(t *testing.T) {
	addr, err := resolveExitNodeAddr(ExitNode{
		Endpoint: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("resolve exit node addr: %v", err)
	}

	if addr.Port != 21820 {
		t.Fatalf("expected default relay port 21820, got %d", addr.Port)
	}
}

func TestAddExitNodeBeforeStartStoresNodeWithoutRunningContext(t *testing.T) {
	m := NewManager("newt-id", "newt", "public-key", testLogger())

	if err := m.AddExitNode(ExitNode{
		ID:        "one",
		Endpoint:  "127.0.0.1",
		RelayPort: 21820,
		PublicKey: "pk1",
	}); err != nil {
		t.Fatalf("add exit node: %v", err)
	}

	nodes := m.GetNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected one exit node, got %d", len(nodes))
	}
}

func TestStartHandlesPreSeededExitNodes(t *testing.T) {
	m := NewManager("newt-id", "newt", "public-key", testLogger())
	if err := m.SyncExitNodes([]ExitNode{
		{ID: "one", Endpoint: "127.0.0.1", RelayPort: 21820, PublicKey: "pk1"},
	}); err != nil {
		t.Fatalf("sync exit nodes: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := m.Start(ctx); err != context.Canceled {
		t.Fatalf("expected canceled context, got %v", err)
	}
}

type stubUDPWriter struct{}

func (stubUDPWriter) WriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	return len(data), nil
}

func TestSetWriterBeforeStartStoresWriter(t *testing.T) {
	m := NewManager("newt-id", "newt", "public-key", testLogger())
	writer := stubUDPWriter{}
	m.SetWriter(writer)

	if m.writer == nil {
		t.Fatal("expected writer to be stored")
	}
}

func TestStartHandlesPreconfiguredWriter(t *testing.T) {
	m := NewManager("newt-id", "newt", "public-key", testLogger())
	m.SetWriter(stubUDPWriter{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := m.Start(ctx); err != context.Canceled {
		t.Fatalf("expected canceled context, got %v", err)
	}
}

func TestNextHolePunchIntervalUsesLegacyBackoff(t *testing.T) {
	if got := nextHolePunchInterval(0); got != initialBackoff {
		t.Fatalf("interval from zero = %v, want %v", got, initialBackoff)
	}
	if got := nextHolePunchInterval(initialBackoff); got != 2*time.Second {
		t.Fatalf("interval from initial = %v, want 2s", got)
	}
	if got := nextHolePunchInterval(32 * time.Second); got != maxBackoff {
		t.Fatalf("interval near cap = %v, want %v", got, maxBackoff)
	}
	if got := nextHolePunchInterval(maxBackoff); got != maxBackoff {
		t.Fatalf("interval at cap = %v, want %v", got, maxBackoff)
	}
}
