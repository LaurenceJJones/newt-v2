package forwarding

import (
	"context"
	"net/netip"
	"testing"

	"github.com/fosrl/newt/internal/netstack/rules"
)

func TestPlanICMPDropsWithoutRule(t *testing.T) {
	decision, err := PlanICMP(
		context.Background(),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("192.168.0.20"),
		rules.NewLookup(),
		staticResolver{},
	)
	if err != nil {
		t.Fatalf("plan icmp: %v", err)
	}
	if decision.Action != ICMPActionDrop {
		t.Fatalf("expected drop, got %v", decision.Action)
	}
}

func TestPlanICMPPreservesOriginalWithoutRewrite(t *testing.T) {
	lookup := rules.NewLookup()
	lookup.Add(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
		"",
		nil,
		false,
	)

	decision, err := PlanICMP(
		context.Background(),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("192.168.0.20"),
		lookup,
		staticResolver{},
	)
	if err != nil {
		t.Fatalf("plan icmp: %v", err)
	}
	if decision.Action != ICMPActionProxy {
		t.Fatalf("expected proxy, got %v", decision.Action)
	}
	if decision.Rewritten {
		t.Fatal("expected original destination")
	}
	if decision.Effective != netip.MustParseAddr("192.168.0.20") {
		t.Fatalf("unexpected destination: %s", decision.Effective)
	}
}

func TestPlanICMPUsesResolvedRewrite(t *testing.T) {
	lookup := rules.NewLookup()
	lookup.Add(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/24"),
		"localhost",
		nil,
		false,
	)

	decision, err := PlanICMP(
		context.Background(),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("192.168.0.20"),
		lookup,
		staticResolver{addr: netip.MustParseAddr("127.0.0.1")},
	)
	if err != nil {
		t.Fatalf("plan icmp: %v", err)
	}
	if decision.Action != ICMPActionProxy {
		t.Fatalf("expected proxy, got %v", decision.Action)
	}
	if !decision.Rewritten {
		t.Fatal("expected rewritten destination")
	}
	if decision.Effective != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("unexpected rewritten destination: %s", decision.Effective)
	}
}
