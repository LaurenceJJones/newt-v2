package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/fosrl/newt/internal/netstack/dnsclient"
)

var (
	ErrNumericPort       = errors.New("port must be numeric")
	ErrNoSuitableAddress = errors.New("no suitable address found")
	ErrMissingAddress    = errors.New("missing address")
)

type Resolver interface {
	LookupContextHost(ctx context.Context, host string) ([]string, error)
}

type Callbacks struct {
	Resolve  Resolver
	DialTCP  func(context.Context, netip.AddrPort) (net.Conn, error)
	DialUDP  func(netip.AddrPort, netip.AddrPort) (net.Conn, error)
	DialPing func(netip.Addr) (net.Conn, error)
}

func DialContext(ctx context.Context, network, address string, cb Callbacks) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}

	proto, acceptV4, acceptV6, err := parseNetwork(network)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	host, port, err := splitAddress(proto, address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	allAddr, err := cb.Resolve.LookupContextHost(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	addrs := filterAddresses(allAddr, uint16(port), acceptV4, acceptV6)
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &net.OpError{Op: "dial", Err: ErrNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			switch err {
			case context.Canceled:
				err = dnsclient.ErrCanceled
			case context.DeadlineExceeded:
				err = dnsclient.ErrTimeout
			}
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := dnsclient.PartialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		var conn net.Conn
		switch proto {
		case "tcp":
			conn, err = cb.DialTCP(dialCtx, addr)
		case "udp":
			conn, err = cb.DialUDP(netip.AddrPort{}, addr)
		case "ping":
			conn, err = cb.DialPing(addr.Addr())
		}
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: ErrMissingAddress}
	}
	return nil, firstErr
}

func parseNetwork(network string) (proto string, acceptV4, acceptV6 bool, err error) {
	matches := dnsclient.ProtoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return "", false, false, net.UnknownNetworkError(network)
	}
	proto = matches[1]
	if len(matches[2]) == 0 {
		return proto, true, true, nil
	}
	acceptV4 = matches[2][0] == '4'
	acceptV6 = !acceptV4
	return proto, acceptV4, acceptV6, nil
}

func splitAddress(proto, address string) (host string, port int, err error) {
	if proto == "ping" {
		return address, 0, nil
	}
	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, ErrNumericPort
	}
	return host, port, nil
}

func filterAddresses(addresses []string, port uint16, acceptV4, acceptV6 bool) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(addresses))
	for _, raw := range addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if (ip.Is4() && acceptV4) || (ip.Is6() && acceptV6) {
			out = append(out, netip.AddrPortFrom(ip, port))
		}
	}
	return out
}
