package rewrite

import (
	"net/netip"
	"testing"
)

func TestStateTracksForwardAndReverseMappings(t *testing.T) {
	s := NewState()
	originalDst := netip.MustParseAddr("192.168.1.10")
	rewrittenTo := netip.MustParseAddr("127.0.0.1")

	s.RememberConnection("10.0.0.2", 12345, originalDst.String(), 8080, 6, originalDst, rewrittenTo)

	got, ok := s.DestinationRewrite("10.0.0.2", originalDst.String(), 8080, 6)
	if !ok || got != rewrittenTo {
		t.Fatalf("unexpected destination rewrite: %v %v", got, ok)
	}

	got, ok = s.ExistingConnectionRewrite("10.0.0.2", 12345, originalDst.String(), 8080, 6)
	if !ok || got != rewrittenTo {
		t.Fatalf("unexpected connection rewrite: %v %v", got, ok)
	}

	got, ok = s.ReverseTranslation(rewrittenTo.String(), "10.0.0.2", 12345, 8080, 6)
	if !ok || got != originalDst {
		t.Fatalf("unexpected reverse translation: %v %v", got, ok)
	}
}
