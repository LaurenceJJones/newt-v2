package expose

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/lifecycle"
	pkglogger "github.com/fosrl/newt/pkg/logger"
)

func testProxyLogger() *slog.Logger { return pkglogger.Discard() }

func TestParseTargetStringRequiresListenIP(t *testing.T) {
	m := NewManager(nil, "", testProxyLogger())

	if _, err := m.parseTargetString("8080:127.0.0.1:80", "tcp"); err == nil {
		t.Fatal("expected parse to fail without listen IP")
	}
}

func TestParseTargetStringSupportsIPv6Targets(t *testing.T) {
	m := NewManager(nil, "", testProxyLogger())
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
	m := NewManager(nil, "", testProxyLogger())
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
	m := NewManager(nil, "", testProxyLogger())
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

func TestAddTargetUsesUpdownRewrite(t *testing.T) {
	script := filepath.Join(t.TempDir(), "rewrite.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '127.0.0.1:9090'\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	m := NewManager(nil, script, testProxyLogger())
	target := Target{Protocol: "tcp", ListenAddr: "100.64.0.10:8080", TargetAddr: "127.0.0.1:80", Enabled: true}
	if err := m.addTarget(target); err != nil {
		t.Fatalf("add target: %v", err)
	}

	if got := m.PendingCount(); got != 1 {
		t.Fatalf("expected pending target, got %d", got)
	}
	if got := m.pending[0].TargetAddr; got != "127.0.0.1:9090" {
		t.Fatalf("unexpected rewritten target: %q", got)
	}
}

func TestRemoveTargetRunsUpdownForPendingTarget(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "calls.txt")
	script := filepath.Join(dir, "remove.sh")
	content := fmt.Sprintf("#!/bin/sh\nprintf '%%s %%s %%s\\n' \"$1\" \"$2\" \"$3\" >> %s\n", out)
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	m := NewManager(nil, script, testProxyLogger())
	m.listenIP = netip.MustParseAddr("100.64.0.10").String()
	m.pending = []Target{{Protocol: "udp", ListenAddr: "100.64.0.10:5353", TargetAddr: "127.0.0.1:5353", Enabled: true}}

	if err := m.removeTarget(Target{Protocol: "udp", ListenAddr: "100.64.0.10:5353"}); err != nil {
		t.Fatalf("remove target: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got := string(data); got != "remove udp 127.0.0.1:5353\n" {
		t.Fatalf("unexpected updown invocation: %q", got)
	}
}

type stubProxyDialer struct{}

func (d *stubProxyDialer) DialTCP(addr string) (net.Conn, error)         { return nil, nil }
func (d *stubProxyDialer) DialUDP(laddr, raddr string) (net.Conn, error) { return nil, nil }
func (d *stubProxyDialer) ListenTCP(addr string) (net.Listener, error)   { return newTestListener(), nil }
func (d *stubProxyDialer) ListenUDP(addr string) (net.PacketConn, error) {
	return &testPacketConn{}, nil
}
