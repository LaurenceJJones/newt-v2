package dnsclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	ErrNoSuchHost                   = errors.New("no such host")
	errLameReferral                 = errors.New("lame referral")
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")
	errServerMisbehaving            = errors.New("server misbehaving")
	errInvalidDNSResponse           = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")
	ErrCanceled                     = errors.New("operation was canceled")
	ErrTimeout                      = errors.New("i/o timeout")
)

type Client struct {
	dnsServers []netip.Addr
	hasV4      bool
	hasV6      bool
	dialUDP    func(netip.AddrPort, netip.AddrPort) (net.Conn, error)
	dialTCP    func(context.Context, netip.AddrPort) (net.Conn, error)
}

func New(dnsServers []netip.Addr, hasV4, hasV6 bool, dialUDP func(netip.AddrPort, netip.AddrPort) (net.Conn, error), dialTCP func(context.Context, netip.AddrPort) (net.Conn, error)) *Client {
	return &Client{
		dnsServers: dnsServers,
		hasV4:      hasV4,
		hasV6:      hasV6,
		dialUDP:    dialUDP,
		dialTCP:    dialTCP,
	}
}

func (c *Client) LookupHost(host string) ([]string, error) {
	return c.LookupContextHost(context.Background(), host)
}

func (c *Client) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!c.hasV6 && !c.hasV4) {
		return nil, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}

	if !isDomainName(host) {
		return nil, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: host, IsNotFound: true}
	}

	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}

	var addrsV4, addrsV6 []netip.Addr
	lanes := 0
	if c.hasV4 {
		lanes++
	}
	if c.hasV6 {
		lanes++
	}
	lane := make(chan result, lanes)
	var lastErr error
	if c.hasV4 {
		go func() {
			p, server, err := c.tryOneName(ctx, host+".", dnsmessage.TypeA)
			lane <- result{p, server, err}
		}()
	}
	if c.hasV6 {
		go func() {
			p, server, err := c.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)
			lane <- result{p, server, err}
		}()
	}
	for i := 0; i < lanes; i++ {
		result := <-lane
		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}

	loop:
		for {
			h, err := result.p.AnswerHeader()
			if err != nil && err != dnsmessage.ErrSectionDone {
				lastErr = &net.DNSError{
					Err:    errCannotMarshalDNSMessage.Error(),
					Name:   host,
					Server: result.server,
				}
			}
			if err != nil {
				break
			}
			switch h.Type {
			case dnsmessage.TypeA:
				a, err := result.p.AResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV4 = append(addrsV4, netip.AddrFrom4(a.A))
			case dnsmessage.TypeAAAA:
				aaaa, err := result.p.AAAAResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV6 = append(addrsV6, netip.AddrFrom16(aaaa.AAAA))
			default:
				if err := result.p.SkipAnswer(); err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
			}
		}
	}

	var addrs []netip.Addr
	if c.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}
	if len(addrs) == 0 && lastErr != nil {
		return nil, lastErr
	}

	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.String())
	}
	return out, nil
}

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	return last != '-' && partlen <= 63 && nonNumeric
}

func randU16() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b[:])
}

func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = randU16()
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, err
}

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response || reqID != respHdr.ID {
		return false
	}
	return reqQues.Type == respQues.Type && reqQues.Class == respQues.Class && equalASCIIName(reqQues.Name, respQues.Name)
}

func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 1280)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

func (c *Client) exchange(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}

	for _, useUDP := range []bool{true, false} {
		attemptCtx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		var conn net.Conn
		if useUDP {
			conn, err = c.dialUDP(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
		} else {
			conn, err = c.dialTCP(attemptCtx, netip.AddrPortFrom(server, 53))
		}
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := attemptCtx.Deadline(); ok && !d.IsZero() {
			if err := conn.SetDeadline(d); err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}

		var p dnsmessage.Parser
		var h dnsmessage.Header
		if useUDP {
			p, h, err = dnsPacketRoundTrip(conn, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(conn, id, q, tcpReq)
		}
		_ = conn.Close()
		if err != nil {
			if err == context.Canceled {
				err = ErrCanceled
			} else if err == context.DeadlineExceeded {
				err = ErrTimeout
			}
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		if h.Truncated {
			continue
		}
		return p, h, nil
	}

	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return ErrNoSuchHost
	}
	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}
	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return ErrNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func (c *Client) tryOneName(ctx context.Context, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}

	for i := 0; i < 2; i++ {
		for _, server := range c.dnsServers {
			p, h, err := c.exchange(ctx, server, q, 5*time.Second)
			if err != nil {
				dnsErr := &net.DNSError{Err: err.Error(), Name: name, Server: server.String()}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					dnsErr.IsTimeout = true
				}
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}
			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{Err: err.Error(), Name: name, Server: server.String()}
				if err == errServerTemporarilyMisbehaving {
					dnsErr.IsTemporary = true
				}
				if err == ErrNoSuchHost {
					dnsErr.IsNotFound = true
					return p, server.String(), dnsErr
				}
				lastErr = dnsErr
				continue
			}
			err = skipToAnswer(&p, qtype)
			if err == nil {
				return p, server.String(), nil
			}
			lastErr = &net.DNSError{Err: err.Error(), Name: name, Server: server.String()}
			if err == ErrNoSuchHost {
				lastErr.(*net.DNSError).IsNotFound = true
				return p, server.String(), lastErr
			}
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

var ProtoSplitter = regexp.MustCompile(`^(tcp|udp|ping)(4|6)?$`)

func PartialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, ErrTimeout
	}
	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}
