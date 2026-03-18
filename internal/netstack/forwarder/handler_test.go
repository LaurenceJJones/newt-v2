package proxy

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type notifySink struct{}

func (notifySink) WriteNotify() {}

func TestInitializeAddsIPv4AndIPv6DefaultRoutes(t *testing.T) {
	handler, err := NewHandlerWithFlags(true, true, true, 1280)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	defer handler.Close()

	if err := handler.Initialize(notifySink{}); err != nil {
		t.Fatalf("initialize handler: %v", err)
	}

	routes := handler.proxyStack.GetRouteTable()
	if len(routes) != 2 {
		t.Fatalf("expected 2 default routes, got %d", len(routes))
	}
	if got := routes[0].Destination.String(); got != header.IPv4EmptySubnet.String() {
		t.Fatalf("unexpected first route destination: %s", got)
	}
	if got := routes[1].Destination.String(); got != header.IPv6EmptySubnet.String() {
		t.Fatalf("unexpected second route destination: %s", got)
	}
}
