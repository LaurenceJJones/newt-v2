// Package holepunch provides NAT hole punching for peer connectivity.
package holepunch

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type udpWriter interface {
	WriteToUDP(data []byte, addr *net.UDPAddr) (int, error)
}

const (
	// magicHeader is the prefix for holepunch packets
	magicHeader = "NEWT_HP"

	// initialBackoff matches legacy newt's initial hole-punch cadence.
	initialBackoff = 1 * time.Second

	// maxBackoff matches legacy newt's maximum hole-punch cadence.
	maxBackoff = 60 * time.Second
)

// ExitNode represents an exit node for hole punching.
type ExitNode struct {
	ID        string
	Name      string
	Endpoint  string
	RelayPort uint16
	PublicKey string
	Active    bool
}

// Manager coordinates NAT hole punching with exit nodes.
type Manager struct {
	logger *slog.Logger

	// Shared key for encrypting keepalives
	sharedKey []byte
	id        string
	token     string
	publicKey string
	clientType string

	// UDP socket
	mu     sync.RWMutex
	writer udpWriter

	// Exit nodes
	nodes    map[string]*nodeState
	nodesMu  sync.RWMutex

	// Statistics
	packetsSent atomic.Int64
	packetsRecv atomic.Int64
	errors      atomic.Int64

	// Lifecycle
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

// nodeState tracks the state of an exit node.
type nodeState struct {
	node       ExitNode
	addr       *net.UDPAddr
	lastSeen   atomic.Int64
	punchCount atomic.Int64
	connected  atomic.Bool
	backoff    time.Duration
}

// NewManager creates a new hole punch manager.
func NewManager(id, clientType, publicKey string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		logger:     logger,
		nodes:      make(map[string]*nodeState),
		id:         id,
		clientType: clientType,
		publicKey:  publicKey,
	}
}

// SetSharedKey sets the encryption key for keepalive packets.
func (m *Manager) SetSharedKey(key []byte) {
	m.sharedKey = key
}

// SetToken updates the authentication token used for hole punching.
func (m *Manager) SetToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
}

// Name returns the component name.
func (m *Manager) Name() string {
	return "holepunch"
}

// Start begins hole punching operations.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.started = true
	m.mu.Unlock()

	m.logger.Info("hole punch manager started")

	m.nodesMu.RLock()
	states := make([]*nodeState, 0, len(m.nodes))
	for _, state := range m.nodes {
		states = append(states, state)
	}
	m.nodesMu.RUnlock()

	for _, state := range states {
		m.startPunchLoop(state)
	}

	// Wait for context cancellation
	<-m.ctx.Done()

	m.stopAll()
	return m.ctx.Err()
}

// AddExitNode adds an exit node for hole punching.
func (m *Manager) AddExitNode(node ExitNode) error {
	addr, err := resolveExitNodeAddr(node)
	if err != nil {
		return fmt.Errorf("resolve endpoint %s: %w", node.Endpoint, err)
	}

	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()

	// Remove existing node if present
	if existing, ok := m.nodes[node.ID]; ok {
		existing.connected.Store(false)
	}

	state := &nodeState{
		node:    node,
		addr:    addr,
		backoff: initialBackoff,
	}
	state.lastSeen.Store(time.Now().Unix())

	m.nodes[node.ID] = state

	m.startPunchLoop(state)

	m.logger.Info("added exit node",
		"id", node.ID,
		"endpoint", node.Endpoint,
	)

	return nil
}

// SyncExitNodes replaces the current exit node set with the provided list.
func (m *Manager) SyncExitNodes(nodes []ExitNode) error {
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()

	current := make(map[string]*nodeState, len(nodes))
	for _, node := range nodes {
		addr, err := resolveExitNodeAddr(node)
		if err != nil {
			return fmt.Errorf("resolve endpoint %s: %w", node.Endpoint, err)
		}
		state := &nodeState{
			node:    node,
			addr:    addr,
			backoff: initialBackoff,
		}
		state.lastSeen.Store(time.Now().Unix())
		current[node.ID] = state
	}

	m.nodes = current
	for _, state := range current {
		m.startPunchLoop(state)
	}
	return nil
}

// RemoveExitNode removes an exit node.
func (m *Manager) RemoveExitNode(id string) {
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()

	if state, ok := m.nodes[id]; ok {
		state.connected.Store(false)
		delete(m.nodes, id)
		m.logger.Info("removed exit node", "id", id)
	}
}

// SetWriter sets the UDP writer used for hole punch packets.
func (m *Manager) SetWriter(writer udpWriter) {
	m.mu.Lock()
	m.writer = writer
	m.mu.Unlock()
}

// punchLoop sends periodic hole punch packets to a node.
func (m *Manager) punchLoop(state *nodeState) {
	defer m.wg.Done()

	timer := time.NewTimer(0) // Send immediately
	defer timer.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-timer.C:
			// Check if node still exists
			m.nodesMu.RLock()
			current, exists := m.nodes[state.node.ID]
			m.nodesMu.RUnlock()

			if !exists || current != state {
				return
			}

			// Send punch packet
			if err := m.sendPunch(state); err != nil {
				m.logger.Debug("punch failed",
					"node", state.node.ID,
					"error", err,
				)
				m.errors.Add(1)
			} else {
				state.punchCount.Add(1)
				m.packetsSent.Add(1)
				if !state.connected.Load() {
					state.connected.Store(true)
				}
			}

			interval := nextHolePunchInterval(state.backoff)
			state.backoff = interval
			timer.Reset(interval)
		}
	}
}

func (m *Manager) startPunchLoop(state *nodeState) {
	if state == nil || m.ctx == nil {
		return
	}
	m.wg.Add(1)
	go m.punchLoop(state)
}

// sendPunch sends a hole punch packet to a node.
func (m *Manager) sendPunch(state *nodeState) error {
	m.mu.RLock()
	writer := m.writer
	m.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("no udp writer")
	}

	// Build packet
	packet, err := m.buildPunchPacket(state.node.PublicKey)
	if err != nil {
		return fmt.Errorf("build packet: %w", err)
	}

	if _, err := writer.WriteToUDP(packet, state.addr); err != nil {
		return err
	}

	m.logger.Debug("hole punch sent",
		"node", state.node.ID,
		"endpoint", state.addr.String(),
		"relay_port", state.node.RelayPort,
		"packet_bytes", len(packet),
	)
	return nil
}

// buildPunchPacket creates an encrypted keepalive packet.
func (m *Manager) buildPunchPacket(serverPublicKey string) ([]byte, error) {
	m.mu.RLock()
	token := m.token
	id := m.id
	clientType := m.clientType
	publicKey := m.publicKey
	sharedKey := m.sharedKey
	m.mu.RUnlock()

	if serverPublicKey != "" && token != "" && publicKey != "" {
		var payload any
		if clientType == "newt" {
			payload = struct {
				ID        string `json:"newtId"`
				Token     string `json:"token"`
				PublicKey string `json:"publicKey"`
			}{
				ID:        id,
				Token:     token,
				PublicKey: publicKey,
			}
		} else {
			payload = struct {
				ID        string `json:"olmId"`
				Token     string `json:"token"`
				PublicKey string `json:"publicKey"`
			}{
				ID:        id,
				Token:     token,
				PublicKey: publicKey,
			}
		}

		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}

		encrypted, err := encryptPayload(payloadBytes, serverPublicKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt payload: %w", err)
		}

		packet, err := json.Marshal(encrypted)
		if err != nil {
			return nil, fmt.Errorf("marshal encrypted payload: %w", err)
		}
		return packet, nil
	}

	if serverPublicKey == "" || token == "" || publicKey == "" {
		m.logger.Debug("hole punch encrypted payload unavailable",
			"has_server_public_key", serverPublicKey != "",
			"has_token", token != "",
			"has_public_key", publicKey != "",
			"client_type", clientType,
			"id", id,
		)
	}

	if len(sharedKey) == 0 {
		// Send unencrypted magic header
		return []byte(magicHeader), nil
	}

	// Create AEAD
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Plaintext is timestamp
	plaintext := make([]byte, 8)
	binary.BigEndian.PutUint64(plaintext, uint64(time.Now().UnixNano()))

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(magicHeader))

	// Packet format: magic + nonce + ciphertext
	packet := make([]byte, len(magicHeader)+len(nonce)+len(ciphertext))
	copy(packet, magicHeader)
	copy(packet[len(magicHeader):], nonce)
	copy(packet[len(magicHeader)+len(nonce):], ciphertext)

	return packet, nil
}

// TriggerHolePunch sends an immediate hole punch to all configured exit nodes.
func (m *Manager) TriggerHolePunch() error {
	m.nodesMu.RLock()
	states := make([]*nodeState, 0, len(m.nodes))
	for _, state := range m.nodes {
		states = append(states, state)
	}
	m.nodesMu.RUnlock()

	if len(states) == 0 {
		return fmt.Errorf("no exit nodes configured")
	}

	var sent int
	for _, state := range states {
		if err := m.sendPunch(state); err != nil {
			m.logger.Debug("triggered hole punch failed", "node", state.node.ID, "error", err)
			continue
		}
		state.backoff = initialBackoff
		sent++
	}

	if sent == 0 {
		return fmt.Errorf("failed to send hole punch to any exit node")
	}
	return nil
}

func nextHolePunchInterval(current time.Duration) time.Duration {
	if current <= 0 {
		return initialBackoff
	}
	next := current * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

func resolveExitNodeAddr(node ExitNode) (*net.UDPAddr, error) {
	host := node.Endpoint
	if h, _, err := net.SplitHostPort(node.Endpoint); err == nil {
		host = h
	}
	port := node.RelayPort
	if port == 0 {
		port = 21820
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
}

func encryptPayload(payload []byte, serverPublicKey string) (any, error) {
	var ephemeralPrivateKey [32]byte
	if _, err := rand.Read(ephemeralPrivateKey[:]); err != nil {
		return nil, fmt.Errorf("generate ephemeral private key: %w", err)
	}
	ephemeralPrivateKey[0] &= 248
	ephemeralPrivateKey[31] &= 127
	ephemeralPrivateKey[31] |= 64

	var ephemeralPublicKey [32]byte
	curve25519.ScalarBaseMult(&ephemeralPublicKey, &ephemeralPrivateKey)

	serverPubKey, err := base64.StdEncoding.DecodeString(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse server public key: %w", err)
	}
	if len(serverPubKey) != 32 {
		return nil, fmt.Errorf("parse server public key: unexpected length %d", len(serverPubKey))
	}

	sharedSecret, err := curve25519.X25519(ephemeralPrivateKey[:], serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("perform x25519 key exchange: %w", err)
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("create AEAD cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, payload, nil)

	return struct {
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		Nonce              []byte `json:"nonce"`
		Ciphertext         []byte `json:"ciphertext"`
	}{
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralPublicKey[:]),
		Nonce:              nonce,
		Ciphertext:         ciphertext,
	}, nil
}

// stopAll stops all hole punch operations.
func (m *Manager) stopAll() {
	m.mu.Lock()
	m.started = false
	m.nodesMu.Lock()
	for id := range m.nodes {
		delete(m.nodes, id)
	}
	m.nodesMu.Unlock()
	m.mu.Unlock()

	m.wg.Wait()
}

// Shutdown gracefully shuts down the manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	if m.cancel != nil {
		m.cancel()
	}
	m.stopAll()
	return nil
}

// Stats returns current statistics.
func (m *Manager) Stats() (sent, recv, errs int64) {
	return m.packetsSent.Load(), m.packetsRecv.Load(), m.errors.Load()
}

// IsConnected returns whether a node is connected.
func (m *Manager) IsConnected(id string) bool {
	m.nodesMu.RLock()
	defer m.nodesMu.RUnlock()

	if state, ok := m.nodes[id]; ok {
		return state.connected.Load()
	}
	return false
}

// GetNodes returns a snapshot of the configured exit nodes.
func (m *Manager) GetNodes() []ExitNode {
	m.nodesMu.RLock()
	defer m.nodesMu.RUnlock()

	out := make([]ExitNode, 0, len(m.nodes))
	for _, state := range m.nodes {
		out = append(out, state.node)
	}
	return out
}
