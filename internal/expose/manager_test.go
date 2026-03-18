package expose

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/lifecycle"
	pkglogger "github.com/fosrl/newt/pkg/logger"
)

func testProxyLogger() *slog.Logger { return pkglogger.Discard() }

func TestParseTargetStringRequiresListenIP(t *testing.T) {
	m := NewManager(nil, testProxyLogger())

	if _, err := m.parseTargetString("8080:127.0.0.1:80", "tcp"); err == nil {
		t.Fatal("expected parse to fail without listen IP")
	}
}

func TestParseTargetStringSupportsIPv6Targets(t *testing.T) {
	m := NewManager(nil, testProxyLogger())
	m.SetListenIP("100.64.0.10")

	target, err := m.parseTargetString("8080:[2001:db8::10]:443", "tcp")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	if target.ListenAddr != "100.64.0.10:8080" {
		t.Fatalf("unexpected listen addr: %q", target.ListenAddr)
	}
	if target.TargetAddr != "[2001:db8::10]:443" {
		t.Fatalf("unexpected target addr: %q", target.TargetAddr)
	}
}

func TestSyncTargetsPrunesPendingTargets(t *testing.T) {
	m := NewManager(nil, testProxyLogger())
	m.SetListenIP("100.64.0.10")

	if err := m.addTarget(Target{Protocol: "tcp", ListenAddr: "100.64.0.10:8080", TargetAddr: "127.0.0.1:8080"}); err != nil {
		t.Fatalf("add target: %v", err)
	}
	if err := m.addTarget(Target{Protocol: "udp", ListenAddr: "100.64.0.10:5353", TargetAddr: "127.0.0.1:5353"}); err != nil {
		t.Fatalf("add target: %v", err)
	}

	if got := m.PendingCount(); got != 2 {
		t.Fatalf("expected 2 pending targets, got %d", got)
	}

	if err := m.SyncTargets(control.TargetsByType{
		TCP: []string{"8080:127.0.0.1:8080"},
	}); err != nil {
		t.Fatalf("sync targets: %v", err)
	}

	if got := m.PendingCount(); got != 1 {
		t.Fatalf("expected 1 pending target after sync, got %d", got)
	}
}

func TestResetClearsRuntimeState(t *testing.T) {
	m := NewManager(nil, testProxyLogger())
	m.group = lifecycle.NewGroup(context.Background())
	m.dialer = &stubProxyDialer{}
	m.listenIP = netip.MustParseAddr("100.64.0.10").String()
	m.pending = []Target{{Protocol: "tcp", ListenAddr: "100.64.0.10:8080", TargetAddr: "127.0.0.1:8080"}}

	m.Reset()

	if got := m.ListenIP(); got != "" {
		t.Fatalf("expected cleared listen ip, got %q", got)
	}
	if got := m.PendingCount(); got != 0 {
		t.Fatalf("expected cleared pending targets, got %d", got)
	}
	if m.dialer != nil {
		t.Fatal("expected dialer to be cleared")
	}
}

type stubProxyDialer struct{}

func (d *stubProxyDialer) DialTCP(addr string) (net.Conn, error)         { return nil, nil }
func (d *stubProxyDialer) DialUDP(laddr, raddr string) (net.Conn, error) { return nil, nil }
func (d *stubProxyDialer) ListenTCP(addr string) (net.Listener, error)   { return newTestListener(), nil }
func (d *stubProxyDialer) ListenUDP(addr string) (net.PacketConn, error) { return &testPacketConn{}, nil }
