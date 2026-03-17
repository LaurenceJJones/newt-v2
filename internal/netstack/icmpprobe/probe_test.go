package icmpprobe

import (
	"testing"
	"time"
)

func TestProbeFallsBackInOrder(t *testing.T) {
	p := New(5 * time.Second)

	var calls []string
	p.tryRawICMPFn = func(actualDstIP string, ident, seq uint16, payload []byte, ignoreIdent bool) bool {
		calls = append(calls, "raw")
		return false
	}
	p.tryUnprivilegedICMPFn = func(actualDstIP string, ident, seq uint16, payload []byte) bool {
		calls = append(calls, "udp")
		return false
	}
	p.tryPingCommandFn = func(actualDstIP string, ident, seq uint16, payload []byte) bool {
		calls = append(calls, "cmd")
		return true
	}

	method, ok := p.Probe("127.0.0.1", 1, 1, nil)
	if !ok {
		t.Fatal("expected probe success")
	}
	if method != "ping command" {
		t.Fatalf("unexpected method: %q", method)
	}
	if len(calls) != 3 || calls[0] != "raw" || calls[1] != "udp" || calls[2] != "cmd" {
		t.Fatalf("unexpected call order: %v", calls)
	}
}
