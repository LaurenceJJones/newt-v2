package icmpprobe

import (
	"context"
	"net"
	"os/exec"
	"time"

	"github.com/fosrl/newt/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Prober struct {
	Timeout time.Duration

	tryRawICMPFn          func(actualDstIP string, ident, seq uint16, payload []byte, ignoreIdent bool) bool
	tryUnprivilegedICMPFn func(actualDstIP string, ident, seq uint16, payload []byte) bool
	tryPingCommandFn      func(actualDstIP string, ident, seq uint16, payload []byte) bool
}

func New(timeout time.Duration) *Prober {
	p := &Prober{Timeout: timeout}
	p.tryRawICMPFn = p.tryRawICMP
	p.tryUnprivilegedICMPFn = p.tryUnprivilegedICMP
	p.tryPingCommandFn = p.tryPingCommand
	return p
}

func (p *Prober) Probe(actualDstIP string, ident, seq uint16, payload []byte) (string, bool) {
	if p.tryRawICMPFn(actualDstIP, ident, seq, payload, false) {
		return "raw ICMP", true
	}
	if p.tryUnprivilegedICMPFn(actualDstIP, ident, seq, payload) {
		return "unprivileged ICMP", true
	}
	if p.tryPingCommandFn(actualDstIP, ident, seq, payload) {
		return "ping command", true
	}
	return "", false
}

func (p *Prober) tryRawICMP(actualDstIP string, ident, seq uint16, payload []byte, ignoreIdent bool) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		logger.Debug("ICMP probe: raw socket unavailable: %v", err)
		return false
	}
	defer conn.Close()

	return p.sendAndReceiveICMP(conn, actualDstIP, ident, seq, payload, false, ignoreIdent)
}

func (p *Prober) tryUnprivilegedICMP(actualDstIP string, ident, seq uint16, payload []byte) bool {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		logger.Debug("ICMP probe: unprivileged socket unavailable: %v", err)
		return false
	}
	defer conn.Close()

	return p.sendAndReceiveICMP(conn, actualDstIP, ident, seq, payload, true, true)
}

func (p *Prober) sendAndReceiveICMP(conn *icmp.PacketConn, actualDstIP string, ident, seq uint16, payload []byte, isUnprivileged bool, ignoreIdent bool) bool {
	echoMsg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(ident),
			Seq:  int(seq),
			Data: payload,
		},
	}

	msgBytes, err := echoMsg.Marshal(nil)
	if err != nil {
		logger.Debug("ICMP probe: marshal failed: %v", err)
		return false
	}

	conn.SetDeadline(time.Now().Add(p.Timeout))

	if isUnprivileged {
		udpAddr := &net.UDPAddr{IP: net.ParseIP(actualDstIP)}
		_, err = conn.WriteTo(msgBytes, udpAddr)
	} else {
		dst, resolveErr := net.ResolveIPAddr("ip4", actualDstIP)
		if resolveErr != nil {
			logger.Debug("ICMP probe: resolve %s failed: %v", actualDstIP, resolveErr)
			return false
		}
		_, err = conn.WriteTo(msgBytes, dst)
	}
	if err != nil {
		logger.Debug("ICMP probe: send to %s failed: %v", actualDstIP, err)
		return false
	}

	replyBuf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(replyBuf)
		if err != nil {
			logger.Debug("ICMP probe: receive from %s failed: %v", actualDstIP, err)
			return false
		}

		replyMsg, err := icmp.ParseMessage(1, replyBuf[:n])
		if err != nil {
			continue
		}
		if replyMsg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		reply, ok := replyMsg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if reply.Seq != int(seq) {
			continue
		}
		if !ignoreIdent && reply.ID != int(ident) {
			continue
		}
		return true
	}
}

func (p *Prober) tryPingCommand(actualDstIP string, ident, seq uint16, payload []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", "-q", actualDstIP)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debug("ICMP probe: ping command failed: %v, output: %s", err, string(output))
		return false
	}
	return true
}
