package forwarding

import (
	"net/netip"
	"testing"
)

type staticDestinationRewriter struct {
	addr netip.Addr
	ok   bool
}

func (r staticDestinationRewriter) LookupDestinationRewrite(srcIP, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool) {
	return r.addr, r.ok
}

func TestResolveTargetReturnsOriginalWhenNoRewriteExists(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.2")
	dst := netip.MustParseAddr("192.168.0.20")

	target := ResolveTarget(src, dst, 8080, 6, staticDestinationRewriter{})

	if target.Rewritten {
		t.Fatal("expected original target")
	}
	if target.Original != netip.MustParseAddrPort("192.168.0.20:8080") {
		t.Fatalf("unexpected original target: %s", target.Original)
	}
	if target.Effective != target.Original {
		t.Fatalf("expected effective target to remain original, got %s", target.Effective)
	}
}

func TestResolveTargetUsesRewrittenDestination(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.2")
	dst := netip.MustParseAddr("192.168.0.20")

	target := ResolveTarget(src, dst, 8080, 17, staticDestinationRewriter{
		addr: netip.MustParseAddr("127.0.0.1"),
		ok:   true,
	})

	if !target.Rewritten {
		t.Fatal("expected rewritten target")
	}
	if target.Original != netip.MustParseAddrPort("192.168.0.20:8080") {
		t.Fatalf("unexpected original target: %s", target.Original)
	}
	if target.Effective != netip.MustParseAddrPort("127.0.0.1:8080") {
		t.Fatalf("unexpected effective target: %s", target.Effective)
	}
}
