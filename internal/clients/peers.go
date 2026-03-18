package clients

import (
	"fmt"

	"github.com/fosrl/newt/internal/control"
	"github.com/fosrl/newt/internal/holepunch"
	"github.com/fosrl/newt/internal/tunnel"
)

func (m *Manager) applyPeers() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.device == nil {
		return nil
	}

	current := make([]control.ClientWGPeer, 0, len(m.peers))
	for _, peer := range m.peers {
		current = append(current, peer)
	}

	for publicKey := range m.appliedPeers {
		if _, ok := m.peers[publicKey]; !ok {
			if err := m.device.RemovePeer(publicKey); err != nil {
				m.logger.Warn("failed to remove stale client peer", "public_key", publicKey, "error", err)
			}
			delete(m.appliedPeers, publicKey)
		}
	}

	for _, peer := range current {
		prefixes, err := parseAllowedIPs(peer.AllowedIPs)
		if err != nil {
			return fmt.Errorf("parse allowed IPs for %s: %w", peer.PublicKey, err)
		}
		if err := m.device.AddPeer(tunnel.PeerConfig{
			PublicKey:           peer.PublicKey,
			Endpoint:            peer.Endpoint,
			AllowedIPs:          prefixes,
			PersistentKeepalive: 25,
		}); err != nil {
			return fmt.Errorf("add peer %s: %w", peer.PublicKey, err)
		}
		m.appliedPeers[peer.PublicKey] = struct{}{}
	}

	return nil
}

func (m *Manager) replacePeers(peers []control.ClientWGPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peers = make(map[string]control.ClientWGPeer, len(peers))
	for _, peer := range peers {
		m.peers[peer.PublicKey] = peer
	}
}

func (m *Manager) storePeer(peer control.ClientWGPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peers[peer.PublicKey] = peer
}

func (m *Manager) deletePeer(publicKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.peers, publicKey)
}

func (m *Manager) mergePeerUpdate(peer control.ClientWGPeer, endpointSpecified bool) (control.ClientWGPeer, *tunnel.Device) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing := m.peers[peer.PublicKey]
	if len(peer.AllowedIPs) > 0 {
		existing.AllowedIPs = peer.AllowedIPs
	}
	if endpointSpecified || existing.PublicKey == "" {
		existing.Endpoint = peer.Endpoint
	}
	existing.PublicKey = peer.PublicKey
	m.peers[peer.PublicKey] = existing
	return existing, m.device
}

func (m *Manager) applyPeerUpdate(existing control.ClientWGPeer, endpointSpecified bool, device *tunnel.Device) error {
	if device == nil {
		return m.applyPeers()
	}

	prefixes, err := parseAllowedIPs(existing.AllowedIPs)
	if err != nil {
		return fmt.Errorf("parse allowed IPs for %s: %w", existing.PublicKey, err)
	}
	if endpointSpecified && existing.Endpoint == "" {
		if err := device.RemovePeer(existing.PublicKey); err != nil {
			return fmt.Errorf("remove peer %s for endpoint clear: %w", existing.PublicKey, err)
		}
		if err := device.AddPeer(tunnel.PeerConfig{
			PublicKey:           existing.PublicKey,
			Endpoint:            "",
			AllowedIPs:          prefixes,
			PersistentKeepalive: 25,
		}); err != nil {
			return fmt.Errorf("re-add peer %s after endpoint clear: %w", existing.PublicKey, err)
		}
		return nil
	}
	if err := device.UpdatePeer(tunnel.PeerConfig{
		PublicKey:           existing.PublicKey,
		Endpoint:            existing.Endpoint,
		AllowedIPs:          prefixes,
		PersistentKeepalive: 25,
	}, endpointSpecified); err != nil {
		return fmt.Errorf("update peer %s: %w", existing.PublicKey, err)
	}
	return nil
}

// StartHolepunch configures the active exit-node relay target used for
// downstream client hole punching.
func (m *Manager) StartHolepunch(publicKey, endpoint string, relayPort uint16) error {
	if m.holePunch == nil {
		return nil
	}
	if relayPort == 0 {
		relayPort = 21820
	}
	if err := m.holePunch.SyncExitNodes([]holepunch.ExitNode{
		{
			ID:        publicKey,
			Name:      publicKey,
			Endpoint:  endpoint,
			RelayPort: relayPort,
			PublicKey: publicKey,
			Active:    true,
		},
	}); err != nil {
		return err
	}
	m.logger.Info("clients hole punch target configured", "endpoint", endpoint, "relay_port", relayPort, "public_key", publicKey)

	return nil
}
