package netstack

import (
	"context"
	"net"
	"net/netip"

	"github.com/fosrl/newt/internal/netstack/dnsclient"
)

func (n *Net) LookupHost(host string) ([]string, error) {
	return n.resolver().LookupHost(host)
}

func (n *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return n.resolver().LookupContextHost(ctx, host)
}

func (n *Net) resolver() *dnsclient.Client {
	return dnsclient.New(
		n.dnsServers,
		n.hasV4,
		n.hasV6,
		func(laddr, raddr netip.AddrPort) (net.Conn, error) {
			return n.DialUDPAddrPort(laddr, raddr)
		},
		func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return n.DialContextTCPAddrPort(ctx, addr)
		},
	)
}
