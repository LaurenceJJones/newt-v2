package clients

import (
	"net/netip"
	"time"

	"github.com/fosrl/newt/internal/tunnel"
)

func noLaterThanNowPlus100ms() time.Time {
	return time.Now().Add(100 * time.Millisecond)
}

func netipAddrPortUnmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func parseCIDRAddr(s string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return prefix.Addr(), nil
}

func parseAllowedIPs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		parsed, err := tunnel.ParseAllowedIPs(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, parsed...)
	}
	return prefixes, nil
}
