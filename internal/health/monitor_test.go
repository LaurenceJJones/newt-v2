package health

import (
	"context"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/lifecycle"
)

func TestParseTargetPreservesMode(t *testing.T) {
	m := NewMonitor(nil, false, nil)

	target := m.parseTarget(control.HealthCheckData{Mode: "tcp"})

	if target.Mode != "tcp" {
		t.Fatalf("expected mode to be preserved, got %q", target.Mode)
	}
}

func TestBuildStatusPayloadPreservesMode(t *testing.T) {
	m := NewMonitor(nil, false, nil)
	m.checkers = map[int]*activeChecker{
		1: {
			target: Target{
				ID:                1,
				Hostname:          "127.0.0.1",
				Port:              8080,
				Path:              "/health",
				Scheme:            "http",
				Mode:              "tcp",
				Method:            "GET",
				ExpectedStatus:    200,
				Headers:           map[string]string{},
				Interval:          30 * time.Second,
				UnhealthyInterval: 10 * time.Second,
				Timeout:           5 * time.Second,
				Enabled:           true,
			},
			checker: &Checker{
				status:     StatusUnknown,
				lastCheck:  time.Unix(0, 0).UTC(),
				checkCount: 1,
			},
		},
	}

	payload := m.buildStatusPayloadLocked()
	targets, ok := payload["targets"].(map[int]any)
	if !ok {
		t.Fatalf("unexpected targets type: %T", payload["targets"])
	}
	entry, ok := targets[1].(map[string]any)
	if !ok {
		t.Fatalf("unexpected target entry type: %T", targets[1])
	}
	config, ok := entry["config"].(control.HealthCheckData)
	if !ok {
		t.Fatalf("unexpected config payload type: %T", entry["config"])
	}
	if config.Mode != "tcp" {
		t.Fatalf("expected mode tcp, got %q", config.Mode)
	}
}

func TestSyncTargetsRemovesStaleTargets(t *testing.T) {
	m := NewMonitor(nil, false, nil)
	if err := m.AddTargets([]control.HealthCheckData{
		{ID: 1, Hostname: "127.0.0.1", Port: 8080},
		{ID: 2, Hostname: "127.0.0.1", Port: 8081},
	}); err != nil {
		t.Fatalf("add targets: %v", err)
	}

	if err := m.SyncTargets([]control.HealthCheckData{
		{ID: 1, Hostname: "127.0.0.1", Port: 8080},
	}); err != nil {
		t.Fatalf("sync targets: %v", err)
	}

	if got := m.TargetCount(); got != 1 {
		t.Fatalf("expected 1 target after sync, got %d", got)
	}
	if _, ok := m.checkers[2]; ok {
		t.Fatal("expected stale target to be removed")
	}
}

func TestResetClearsTrackedTargets(t *testing.T) {
	m := NewMonitor(nil, false, nil)
	m.group = lifecycle.NewGroup(context.Background())
	if err := m.AddTargets([]control.HealthCheckData{
		{ID: 1, Hostname: "127.0.0.1", Port: 8080},
		{ID: 2, Hostname: "127.0.0.1", Port: 8081},
	}); err != nil {
		t.Fatalf("add targets: %v", err)
	}

	m.Reset()

	if got := m.TargetCount(); got != 0 {
		t.Fatalf("expected reset to clear targets, got %d", got)
	}
}

func TestSendStatusWithoutControlClientIsNoop(t *testing.T) {
	m := NewMonitor(nil, false, nil)
	if err := m.sendStatus(); err != nil {
		t.Fatalf("expected nil error without control client, got %v", err)
	}
}
