package netstack

import (
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (d *device) Name() (string, error) { return "go", nil }
func (d *device) File() *os.File        { return nil }

func (d *device) Events() <-chan tun.Event {
	return d.events
}

func (d *device) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-d.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (d *device) Write(buf [][]byte, offset int) (int, error) {
	for _, packetBuf := range buf {
		packet := packetBuf[offset:]
		if len(packet) == 0 {
			continue
		}
		if d.handleForwardedPacket(packet) {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

func (d *device) handleForwardedPacket(packet []byte) bool {
	if d.owner != nil && d.owner.forwarder != nil {
		return d.owner.forwarder.HandleIncomingPacket(packet)
	}
	return false
}

func (d *device) WriteNotify() {
	pkt := d.ep.Read()
	if pkt != nil {
		view := pkt.ToView()
		pkt.DecRef()
		d.incomingPacket <- view
		return
	}
	if d.owner != nil && d.owner.forwarder != nil {
		if view := d.owner.forwarder.ReadOutgoingPacket(); view != nil {
			d.incomingPacket <- view
		}
	}
}

func (d *device) Close() error {
	d.stack.RemoveNIC(1)
	d.stack.Close()
	d.ep.RemoveNotify(d.notifyHandle)
	d.ep.Close()
	if d.owner != nil && d.owner.forwarder != nil {
		_ = d.owner.forwarder.Close()
	}
	closeIfOpen(d.events)
	closeIfOpen(d.incomingPacket)
	return nil
}

func closeIfOpen[T any](ch chan T) {
	if ch != nil {
		close(ch)
	}
}

func (d *device) MTU() (int, error) { return d.mtu, nil }
func (d *device) BatchSize() int    { return 1 }
