package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// resolveEndpoint resolves a hostname:port endpoint to an IP:port endpoint.
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("split host port: %w", err)
	}

	// Check if host is already an IP
	if ip := net.ParseIP(host); ip != nil {
		return endpoint, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("lookup ip: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for %s", host)
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return net.JoinHostPort(ip4.String(), port), nil
		}
	}

	// Fall back to first IP (likely IPv6)
	return net.JoinHostPort(ips[0].String(), port), nil
}

// Device wraps a WireGuard device with simplified configuration.
type Device struct {
	dev  *device.Device
	tun  tun.Device
	bind conn.Bind

	privateKey string // hex encoded
	publicKey  string // base64 encoded
}

// NewDevice creates a new WireGuard device with the given TUN and bind.
// If privateKeyHex is empty, a new keypair will be generated.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger, privateKeyHex string) (*Device, error) {
	dev := device.NewDevice(tunDev, bind, logger)

	var publicKeyBase64 string
	var err error

	if privateKeyHex == "" {
		// Generate new keypair
		privateKeyHex, publicKeyBase64, err = generateKeyPair()
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("generate keypair: %w", err)
		}
	} else {
		// Compute public key from existing private key
		privateKeyBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("decode private key: %w", err)
		}
		var privateKey, publicKey [32]byte
		copy(privateKey[:], privateKeyBytes)
		curve25519.ScalarBaseMult(&publicKey, &privateKey)
		publicKeyBase64 = base64.StdEncoding.EncodeToString(publicKey[:])
	}

	// Configure private key
	config := fmt.Sprintf("private_key=%s\n", privateKeyHex)
	if err := dev.IpcSet(config); err != nil {
		dev.Close()
		return nil, fmt.Errorf("set private key: %w", err)
	}

	return &Device{
		dev:        dev,
		tun:        tunDev,
		bind:       bind,
		privateKey: privateKeyHex,
		publicKey:  publicKeyBase64,
	}, nil
}

// PublicKey returns the device's public key in base64 format.
func (d *Device) PublicKey() string {
	return d.publicKey
}

// AddPeer adds or updates a peer configuration.
func (d *Device) AddPeer(cfg PeerConfig) error {
	return d.configurePeer(cfg, false, cfg.Endpoint != "")
}

// UpdatePeer applies a partial update to an existing peer configuration.
// If endpointSpecified is true and cfg.Endpoint is empty, the peer endpoint is cleared.
func (d *Device) UpdatePeer(cfg PeerConfig, endpointSpecified bool) error {
	return d.configurePeer(cfg, true, endpointSpecified)
}

func (d *Device) configurePeer(cfg PeerConfig, updateOnly, endpointSpecified bool) error {
	config, err := buildPeerConfig(cfg, updateOnly, endpointSpecified)
	if err != nil {
		return err
	}

	if err := d.dev.IpcSet(config); err != nil {
		return fmt.Errorf("configure peer: %w", err)
	}

	return nil
}

func buildPeerConfig(cfg PeerConfig, updateOnly, endpointSpecified bool) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("public_key=%s\n", pubKeyHex))
	if updateOnly {
		sb.WriteString("update_only=true\n")
	}
	if len(cfg.AllowedIPs) > 0 || !updateOnly {
		sb.WriteString("replace_allowed_ips=true\n")
	}
	if endpointSpecified {
		if cfg.Endpoint != "" {
			endpoint, err := resolveEndpoint(cfg.Endpoint)
			if err != nil {
				return "", fmt.Errorf("resolve endpoint: %w", err)
			}
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", endpoint))
		} else {
			sb.WriteString("endpoint=0.0.0.0:0\n")
		}
	}

	for _, prefix := range cfg.AllowedIPs {
		sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", prefix.String()))
	}

	if endpointSpecified && cfg.Endpoint == "" {
		sb.WriteString("persistent_keepalive_interval=0\n")
	} else if cfg.PersistentKeepalive > 0 && cfg.Endpoint != "" {
		sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", cfg.PersistentKeepalive))
	}

	return sb.String(), nil
}

// RemovePeer removes a peer by public key.
func (d *Device) RemovePeer(publicKeyBase64 string) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	config := fmt.Sprintf("public_key=%s\nremove=true\n", pubKeyHex)
	if err := d.dev.IpcSet(config); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	return nil
}

// Up brings the device up.
func (d *Device) Up() error {
	d.dev.Up()
	return nil
}

// Down brings the device down.
func (d *Device) Down() error {
	d.dev.Down()
	return nil
}

// Close shuts down the device.
func (d *Device) Close() {
	d.dev.Close()
}

// Wait blocks until the device is closed.
func (d *Device) Wait() chan struct{} {
	return d.dev.Wait()
}

// IpcGet returns the device's WireGuard IPC state dump.
func (d *Device) IpcGet() (string, error) {
	return d.dev.IpcGet()
}

// generateKeyPair generates a new WireGuard keypair using X25519.
// Returns private key in hex and public key in base64.
func generateKeyPair() (privateHex, publicBase64 string, err error) {
	// Generate random private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return "", "", fmt.Errorf("generate random key: %w", err)
	}

	// Clamp the private key (WireGuard requirement)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Compute public key
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	privateHex = hex.EncodeToString(privateKey[:])
	publicBase64 = base64.StdEncoding.EncodeToString(publicKey[:])

	return privateHex, publicBase64, nil
}

// GenerateKeyPair exposes WireGuard key generation for other internal packages
// that need legacy-compatible public/private key handling.
func GenerateKeyPair() (privateHex, publicBase64 string, err error) {
	return generateKeyPair()
}

// ParseAllowedIPs parses a comma-separated list of CIDR prefixes.
func ParseAllowedIPs(s string) ([]netip.Prefix, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("parse prefix %q: %w", part, err)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
