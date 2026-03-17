package clients

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/bind"
	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/holepunch"
	"github.com/fosrl/newt/internal/tunnel"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type stubPacketConn struct {
	closed bool
}

func (s *stubPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) { return 0, nil, net.ErrClosed }
func (s *stubPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) { return len(p), nil }
func (s *stubPacketConn) Close() error {
	s.closed = true
	return nil
}
func (s *stubPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (s *stubPacketConn) SetDeadline(t time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestProcessPeerBandwidthFirstReadingProducesNoSample(t *testing.T) {
	m := &Manager{
		lastReadings: make(map[string]peerReading),
	}

	got := m.processPeerBandwidth("001122", 100, 200, time.Unix(100, 0))
	if got != nil {
		t.Fatalf("expected no sample on first reading, got %+v", got)
	}
}

func TestProcessPeerBandwidthProducesDiffInMegabytes(t *testing.T) {
	start := time.Unix(100, 0)
	keyHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	m := &Manager{
		lastReadings: map[string]peerReading{
			keyHex: {
				BytesReceived:    1024 * 1024,
				BytesTransmitted: 2 * 1024 * 1024,
				LastChecked:      start,
			},
		},
	}

	got := m.processPeerBandwidth(keyHex, 3*1024*1024, 5*1024*1024, start.Add(10*time.Second))
	if got == nil {
		t.Fatal("expected bandwidth sample")
	}

	if got.BytesIn != 2 {
		t.Fatalf("expected 2 MB in, got %v", got.BytesIn)
	}
	if got.BytesOut != 3 {
		t.Fatalf("expected 3 MB out, got %v", got.BytesOut)
	}

	wantKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if got.PublicKey != wantKey {
		t.Fatalf("expected public key %q, got %q", wantKey, got.PublicKey)
	}
}

func TestProcessPeerBandwidthCounterResetUsesCurrentValues(t *testing.T) {
	start := time.Unix(100, 0)
	m := &Manager{
		lastReadings: map[string]peerReading{
			"abc": {
				BytesReceived:    500,
				BytesTransmitted: 700,
				LastChecked:      start,
			},
		},
	}

	got := m.processPeerBandwidth("abc", 100, 200, start.Add(5*time.Second))
	if got == nil {
		t.Fatal("expected bandwidth sample")
	}
	if got.BytesIn != float64(100)/(1024*1024) {
		t.Fatalf("unexpected bytes in: %v", got.BytesIn)
	}
	if got.BytesOut != float64(200)/(1024*1024) {
		t.Fatalf("unexpected bytes out: %v", got.BytesOut)
	}
}

func TestResolveSourcePrefixesPrefersSourcePrefixes(t *testing.T) {
	target := control.ClientWGTarget{
		SourcePrefix:   "10.0.0.0/24",
		SourcePrefixes: []string{"10.1.0.0/24", "10.2.0.0/24"},
	}

	got := resolveSourcePrefixes(target)
	if len(got) != 2 || got[0] != "10.1.0.0/24" || got[1] != "10.2.0.0/24" {
		t.Fatalf("unexpected source prefixes: %#v", got)
	}
}

func TestNormalizeIPCKeyToBase64FallsBackOnInvalidHex(t *testing.T) {
	if got := normalizeIPCKeyToBase64("not-hex"); got != "not-hex" {
		t.Fatalf("expected fallback string, got %q", got)
	}
}

func TestResetClearsRuntimeState(t *testing.T) {
	sharedBind := &bind.SharedBind{}
	listener := &stubPacketConn{}

	hp := holepunch.NewManager("newt-id", "newt", "public-key", testLogger())
	if err := hp.SyncExitNodes([]holepunch.ExitNode{
		{ID: "peer", Endpoint: "127.0.0.1", RelayPort: 21820, PublicKey: "peer-key"},
	}); err != nil {
		t.Fatalf("seed exit nodes: %v", err)
	}

	sharedBind.SetNetstackConn(listener)

	m := &Manager{
		logger:        testLogger(),
		sharedBind:    sharedBind,
		holePunch:     hp,
		mainNetstack:  &tunnel.NetStack{},
		relayStop:     make(chan struct{}),
		relayListener: listener,
		clientIP:      "100.64.0.2/32",
		appliedPeers:  map[string]struct{}{"peer": {}},
		lastReadings:  map[string]peerReading{"peer": {BytesReceived: 1}},
	}

	m.Reset()

	if m.mainNetstack != nil {
		t.Fatal("expected main netstack to be cleared")
	}
	if m.relayStop != nil {
		t.Fatal("expected relay stop channel to be cleared")
	}
	if m.relayListener != nil {
		t.Fatal("expected relay listener to be cleared")
	}
	if m.clientIP != "" {
		t.Fatalf("expected client IP to be cleared, got %q", m.clientIP)
	}
	if len(m.appliedPeers) != 0 {
		t.Fatalf("expected applied peers to be cleared, got %d", len(m.appliedPeers))
	}
	if len(m.lastReadings) != 0 {
		t.Fatalf("expected last readings to be cleared, got %d", len(m.lastReadings))
	}
	if len(hp.GetNodes()) != 0 {
		t.Fatalf("expected hole punch exit nodes to be cleared, got %d", len(hp.GetNodes()))
	}
	if sharedBind.GetNetstackConn() != nil {
		t.Fatal("expected shared bind netstack connection to be cleared")
	}
	if !listener.closed {
		t.Fatal("expected relay listener to be closed")
	}
}

func TestStartHolepunchSyncsSingleRelayTarget(t *testing.T) {
	m := &Manager{
		logger:    testLogger(),
		holePunch: holepunch.NewManager("newt-id", "newt", "public-key", testLogger()),
	}

	if err := m.StartHolepunch("peer-key", "127.0.0.1", 12345); err != nil {
		t.Fatalf("start hole punch: %v", err)
	}

	nodes := m.holePunch.GetNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected exactly one exit node, got %d", len(nodes))
	}
	if nodes[0].PublicKey != "peer-key" {
		t.Fatalf("expected public key peer-key, got %q", nodes[0].PublicKey)
	}
	if nodes[0].RelayPort != 12345 {
		t.Fatalf("expected relay port 12345, got %d", nodes[0].RelayPort)
	}
}

func TestConfigRequestLoopStopCancelsFutureRequests(t *testing.T) {
	var calls atomic.Int32
	m := &Manager{
		logger:             testLogger(),
		configRequestEvery: 10 * time.Millisecond,
		sendConfigRequestFn: func(ctx context.Context) error {
			calls.Add(1)
			return nil
		},
	}

	m.startConfigRequestLoop()
	time.Sleep(35 * time.Millisecond)
	m.stopConfigRequests()
	before := calls.Load()
	time.Sleep(35 * time.Millisecond)
	after := calls.Load()

	if before == 0 {
		t.Fatal("expected at least one config request before stop")
	}
	if after != before {
		t.Fatalf("expected config requests to stop after cancellation, before=%d after=%d", before, after)
	}
}

func TestConfigRequestLoopRestartReplacesPriorLoop(t *testing.T) {
	var calls atomic.Int32
	m := &Manager{
		logger:             testLogger(),
		configRequestEvery: 10 * time.Millisecond,
		sendConfigRequestFn: func(ctx context.Context) error {
			calls.Add(1)
			return nil
		},
	}

	m.startConfigRequestLoop()
	time.Sleep(25 * time.Millisecond)
	firstCount := calls.Load()

	m.startConfigRequestLoop()
	time.Sleep(25 * time.Millisecond)
	secondCount := calls.Load()
	m.stopConfigRequests()

	if firstCount == 0 {
		t.Fatal("expected first loop to send requests")
	}

	// A replaced loop should continue sending, but not multiply uncontrollably.
	if secondCount > firstCount+5 {
		t.Fatalf("expected restart to replace prior loop, first=%d second=%d", firstCount, secondCount)
	}
}

func TestHandlePeerUpdateClearsEndpointWhenExplicitlyEmpty(t *testing.T) {
	m := &Manager{
		peers: map[string]control.ClientWGPeer{
			"peer-key": {
				PublicKey:  "peer-key",
				AllowedIPs: []string{"10.0.0.2/32"},
				Endpoint:   "198.51.100.5:51820",
			},
		},
	}

	msg := control.Message{
		Data: json.RawMessage(`{"publicKey":"peer-key","endpoint":""}`),
	}

	if err := m.handlePeerUpdate(msg); err != nil {
		t.Fatalf("handle peer update: %v", err)
	}

	if got := m.peers["peer-key"].Endpoint; got != "" {
		t.Fatalf("expected endpoint to be cleared, got %q", got)
	}
}

func TestHandlePeerUpdatePreservesEndpointWhenOmitted(t *testing.T) {
	m := &Manager{
		peers: map[string]control.ClientWGPeer{
			"peer-key": {
				PublicKey:  "peer-key",
				AllowedIPs: []string{"10.0.0.2/32"},
				Endpoint:   "198.51.100.5:51820",
			},
		},
	}

	msg := control.Message{
		Data: json.RawMessage(`{"publicKey":"peer-key","allowedIps":["10.0.0.3/32"]}`),
	}

	if err := m.handlePeerUpdate(msg); err != nil {
		t.Fatalf("handle peer update: %v", err)
	}

	if got := m.peers["peer-key"].Endpoint; got != "198.51.100.5:51820" {
		t.Fatalf("expected endpoint to be preserved, got %q", got)
	}
	if got := m.peers["peer-key"].AllowedIPs; len(got) != 1 || got[0] != "10.0.0.3/32" {
		t.Fatalf("expected allowed IPs to be updated, got %#v", got)
	}
}
