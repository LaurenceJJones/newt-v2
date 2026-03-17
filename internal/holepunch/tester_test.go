package holepunch

import (
	"io"
	"log/slog"
	"testing"
)

func TestTesterResolveEndpointPreservesExplicitPort(t *testing.T) {
	tester := NewTester(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	addr, err := tester.resolveEndpoint("127.0.0.1:43181")
	if err != nil {
		t.Fatalf("resolve endpoint: %v", err)
	}

	if got := addr.Port; got != 43181 {
		t.Fatalf("resolved port = %d, want 43181", got)
	}
}

func TestTesterResolveEndpointDefaultsRelayPortWhenMissing(t *testing.T) {
	tester := NewTester(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	addr, err := tester.resolveEndpoint("127.0.0.1")
	if err != nil {
		t.Fatalf("resolve endpoint: %v", err)
	}

	if got := addr.Port; got != 21820 {
		t.Fatalf("resolved port = %d, want 21820", got)
	}
}
