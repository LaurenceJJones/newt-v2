package control

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	pkglogger "github.com/fosrl/newt/pkg/logger"
)

func testLogger() *slog.Logger { return pkglogger.Discard() }

func TestMarkConnectedSetsStateAndCallsCallback(t *testing.T) {
	var called atomic.Int32
	c := NewClient(DefaultClientConfig(), testLogger())
	c.OnConnect(func() {
		called.Add(1)
	})

	c.markConnected()

	if !c.Connected() {
		t.Fatal("expected client to be marked connected")
	}
	if called.Load() != 1 {
		t.Fatalf("expected connect callback once, got %d", called.Load())
	}
}

func TestMarkDisconnectedSetsStateAndCallsCallback(t *testing.T) {
	var called atomic.Int32
	var gotErr error
	c := NewClient(DefaultClientConfig(), testLogger())
	c.connected.Store(true)
	wantErr := errors.New("boom")
	c.OnDisconnect(func(err error) {
		gotErr = err
		called.Add(1)
	})

	c.markDisconnected(wantErr)

	if c.Connected() {
		t.Fatal("expected client to be marked disconnected")
	}
	if called.Load() != 1 {
		t.Fatalf("expected disconnect callback once, got %d", called.Load())
	}
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("expected disconnect error %v, got %v", wantErr, gotErr)
	}
}

func TestMarkDisconnectedIgnoresCanceledCallback(t *testing.T) {
	var called atomic.Int32
	c := NewClient(DefaultClientConfig(), testLogger())
	c.connected.Store(true)
	c.OnDisconnect(func(error) {
		called.Add(1)
	})

	c.markDisconnected(context.Canceled)

	if called.Load() != 0 {
		t.Fatalf("expected canceled disconnect to skip callback, got %d", called.Load())
	}
	if c.Connected() {
		t.Fatal("expected client to be marked disconnected")
	}
}

type stubReadLoopConn struct {
	closed atomic.Int32
}

func (s *stubReadLoopConn) Close() error {
	s.closed.Add(1)
	return nil
}

func TestInterruptReadOnCancelClosesConn(t *testing.T) {
	conn := &stubReadLoopConn{}
	ctx, cancel := context.WithCancel(context.Background())
	stop := interruptReadOnCancel(ctx, conn)
	cancel()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if conn.closed.Load() == 1 {
			stop()
			return
		}
		time.Sleep(time.Millisecond)
	}
	stop()
	t.Fatalf("expected conn to be closed once, got %d", conn.closed.Load())
}
