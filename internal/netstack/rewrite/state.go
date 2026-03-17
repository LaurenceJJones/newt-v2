package rewrite

import (
	"net/netip"
	"sync"
)

type connKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	proto   uint8
}

type reverseConnKey struct {
	rewrittenTo     string
	originalSrcIP   string
	originalSrcPort uint16
	originalDstPort uint16
	proto           uint8
}

type destinationKey struct {
	srcIP   string
	dstIP   string
	dstPort uint16
	proto   uint8
}

type natEntry struct {
	originalDst netip.Addr
	rewrittenTo netip.Addr
}

// State tracks rewrite/NAT mappings for proxied connections.
type State struct {
	mu               sync.RWMutex
	byConn           map[connKey]natEntry
	byReverseConn    map[reverseConnKey]natEntry
	byDestinationKey map[destinationKey]netip.Addr
}

func NewState() *State {
	return &State{
		byConn:           make(map[connKey]natEntry),
		byReverseConn:    make(map[reverseConnKey]natEntry),
		byDestinationKey: make(map[destinationKey]netip.Addr),
	}
}

func (s *State) DestinationRewrite(srcIP, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	addr, ok := s.byDestinationKey[destinationKey{
		srcIP:   srcIP,
		dstIP:   dstIP,
		dstPort: dstPort,
		proto:   proto,
	}]
	return addr, ok
}

func (s *State) ExistingConnectionRewrite(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.byConn[connKey{
		srcIP:   srcIP,
		srcPort: srcPort,
		dstIP:   dstIP,
		dstPort: dstPort,
		proto:   proto,
	}]
	if !ok {
		return netip.Addr{}, false
	}
	return entry.rewrittenTo, true
}

func (s *State) RememberConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8, originalDst, rewrittenTo netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := natEntry{
		originalDst: originalDst,
		rewrittenTo: rewrittenTo,
	}

	s.byConn[connKey{
		srcIP:   srcIP,
		srcPort: srcPort,
		dstIP:   dstIP,
		dstPort: dstPort,
		proto:   proto,
	}] = entry

	s.byReverseConn[reverseConnKey{
		rewrittenTo:     rewrittenTo.String(),
		originalSrcIP:   srcIP,
		originalSrcPort: srcPort,
		originalDstPort: dstPort,
		proto:           proto,
	}] = entry

	s.byDestinationKey[destinationKey{
		srcIP:   srcIP,
		dstIP:   dstIP,
		dstPort: dstPort,
		proto:   proto,
	}] = rewrittenTo
}

func (s *State) ReverseTranslation(rewrittenSrcIP, originalSrcIP string, originalSrcPort, originalDstPort uint16, proto uint8) (netip.Addr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.byReverseConn[reverseConnKey{
		rewrittenTo:     rewrittenSrcIP,
		originalSrcIP:   originalSrcIP,
		originalSrcPort: originalSrcPort,
		originalDstPort: originalDstPort,
		proto:           proto,
	}]
	if !ok {
		return netip.Addr{}, false
	}
	return entry.originalDst, true
}
