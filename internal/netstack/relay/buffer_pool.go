package relay

import "sync"

var (
	streamBufferPool = sync.Pool{
		New: func() any {
			return make([]byte, defaultBufferSize)
		},
	}
	packetBufferPool = sync.Pool{
		New: func() any {
			return make([]byte, udpBufferSize)
		},
	}
)

func acquireStreamBuffer() []byte {
	return streamBufferPool.Get().([]byte)
}

func releaseStreamBuffer(buf []byte) {
	if cap(buf) < defaultBufferSize {
		return
	}
	buf = buf[:defaultBufferSize]
	clear(buf)
	streamBufferPool.Put(buf)
}

func AcquirePacketBuffer() []byte {
	return packetBufferPool.Get().([]byte)
}

func ReleasePacketBuffer(buf []byte) {
	if cap(buf) < udpBufferSize {
		return
	}
	buf = buf[:udpBufferSize]
	clear(buf)
	packetBufferPool.Put(buf)
}
