package rules

import (
	"net/netip"
	"sync"

	"github.com/gaissmai/bart"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// PortRange limits a rule to an inclusive protocol/port interval.
// An empty Protocol allows both TCP and UDP.
type PortRange struct {
	Min      uint16
	Max      uint16
	Protocol string
}

// SubnetRule describes one proxyable source/destination subnet mapping.
type SubnetRule struct {
	SourcePrefix netip.Prefix
	DestPrefix   netip.Prefix
	DisableIcmp  bool
	RewriteTo    string
	PortRanges   []PortRange
}

// Lookup provides fast source+destination subnet matching using BART tables.
type Lookup struct {
	mu         sync.RWMutex
	sourceTrie *bart.Table[*destTrie]
}

type destTrie struct {
	trie  *bart.Table[[]*SubnetRule]
	rules []*SubnetRule
}

func NewLookup() *Lookup {
	return &Lookup{
		sourceTrie: &bart.Table[*destTrie]{},
	}
}

func (l *Lookup) Add(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange, disableICMP bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rule := &SubnetRule{
		SourcePrefix: sourcePrefix,
		DestPrefix:   destPrefix,
		DisableIcmp:  disableICMP,
		RewriteTo:    rewriteTo,
		PortRanges:   portRanges,
	}

	sourcePrefix = sourcePrefix.Masked()
	destPrefix = destPrefix.Masked()

	destinations, ok := l.sourceTrie.Get(sourcePrefix)
	if !ok {
		destinations = &destTrie{
			trie:  &bart.Table[[]*SubnetRule]{},
			rules: make([]*SubnetRule, 0, 1),
		}
		l.sourceTrie.Insert(sourcePrefix, destinations)
	}

	destinations.trie.Insert(destPrefix, []*SubnetRule{rule})

	filtered := destinations.rules[:0]
	for _, existing := range destinations.rules {
		if !prefixEqual(existing.SourcePrefix, sourcePrefix) || !prefixEqual(existing.DestPrefix, destPrefix) {
			filtered = append(filtered, existing)
		}
	}
	destinations.rules = append(filtered, rule)
}

func (l *Lookup) Remove(sourcePrefix, destPrefix netip.Prefix) {
	l.mu.Lock()
	defer l.mu.Unlock()

	sourcePrefix = sourcePrefix.Masked()
	destPrefix = destPrefix.Masked()

	destinations, ok := l.sourceTrie.Get(sourcePrefix)
	if !ok {
		return
	}

	destinations.trie.Delete(destPrefix)

	filtered := destinations.rules[:0]
	for _, existing := range destinations.rules {
		if !prefixEqual(existing.SourcePrefix, sourcePrefix) || !prefixEqual(existing.DestPrefix, destPrefix) {
			filtered = append(filtered, existing)
		}
	}
	destinations.rules = filtered

	if destinations.trie.Size() == 0 {
		l.sourceTrie.Delete(sourcePrefix)
	}
}

func (l *Lookup) All() []SubnetRule {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var out []SubnetRule
	for _, destinations := range l.sourceTrie.All() {
		if destinations == nil {
			continue
		}
		for _, rule := range destinations.rules {
			out = append(out, *rule)
		}
	}
	return out
}

func (l *Lookup) Match(srcIP, dstIP netip.Addr, port uint16, proto tcpip.TransportProtocolNumber) *SubnetRule {
	l.mu.RLock()
	defer l.mu.RUnlock()

	srcPrefix := netip.PrefixFrom(srcIP, srcIP.BitLen())
	dstPrefix := netip.PrefixFrom(dstIP, dstIP.BitLen())

	for _, destinations := range l.sourceTrie.Supernets(srcPrefix) {
		if destinations == nil {
			continue
		}
		for _, candidates := range destinations.trie.Supernets(dstPrefix) {
			if candidates == nil {
				continue
			}
			for _, rule := range candidates {
				if proto == header.ICMPv4ProtocolNumber || proto == header.ICMPv6ProtocolNumber {
					if rule.DisableIcmp {
						return nil
					}
					return rule
				}
				if len(rule.PortRanges) == 0 {
					return rule
				}
				for _, pr := range rule.PortRanges {
					if port < pr.Min || port > pr.Max {
						continue
					}
					if pr.Protocol == "" ||
						(pr.Protocol == "tcp" && proto == header.TCPProtocolNumber) ||
						(pr.Protocol == "udp" && proto == header.UDPProtocolNumber) {
						return rule
					}
				}
			}
		}
	}

	return nil
}

func prefixEqual(a, b netip.Prefix) bool {
	return a.Masked() == b.Masked()
}
