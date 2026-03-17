package tunnel

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestConfigurePeerClearsEndpointWhenExplicitlyRequested(t *testing.T) {
	pubKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	cfgText, err := buildPeerConfig(PeerConfig{
		PublicKey:           pubKey,
		Endpoint:            "",
		PersistentKeepalive: 25,
	}, true, true)
	if err != nil {
		t.Fatalf("build peer config: %v", err)
	}

	if !strings.Contains(cfgText, "update_only=true\n") {
		t.Fatalf("expected update_only flag, got:\n%s", cfgText)
	}
	if !strings.Contains(cfgText, "endpoint=0.0.0.0:0\n") {
		t.Fatalf("expected explicit endpoint clear, got:\n%s", cfgText)
	}
	if !strings.Contains(cfgText, "persistent_keepalive_interval=0\n") {
		t.Fatalf("expected keepalive to be cleared with endpoint removal, got:\n%s", cfgText)
	}
}

func TestConfigurePeerPreservesEndpointWhenNotSpecified(t *testing.T) {
	pubKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	cfgText, err := buildPeerConfig(PeerConfig{
		PublicKey:           pubKey,
		Endpoint:            "",
		PersistentKeepalive: 25,
	}, true, false)
	if err != nil {
		t.Fatalf("build peer config: %v", err)
	}

	if strings.Contains(cfgText, "endpoint=") {
		t.Fatalf("did not expect endpoint config when field omitted, got:\n%s", cfgText)
	}
}

func TestAddPeerOmitsEmptyEndpoint(t *testing.T) {
	pubKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	cfgText, err := buildPeerConfig(PeerConfig{
		PublicKey:           pubKey,
		Endpoint:            "",
		PersistentKeepalive: 25,
	}, false, false)
	if err != nil {
		t.Fatalf("build peer config: %v", err)
	}

	if strings.Contains(cfgText, "endpoint=") {
		t.Fatalf("did not expect endpoint config for empty add endpoint, got:\n%s", cfgText)
	}
	if strings.Contains(cfgText, "persistent_keepalive_interval=") {
		t.Fatalf("did not expect keepalive for add without endpoint, got:\n%s", cfgText)
	}
}

func TestAddPeerIncludesKeepaliveWhenEndpointPresent(t *testing.T) {
	pubKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	cfgText, err := buildPeerConfig(PeerConfig{
		PublicKey:           pubKey,
		Endpoint:            "198.51.100.10:51820",
		PersistentKeepalive: 25,
	}, false, true)
	if err != nil {
		t.Fatalf("build peer config: %v", err)
	}

	if !strings.Contains(cfgText, "endpoint=198.51.100.10:51820\n") {
		t.Fatalf("expected endpoint to be configured, got:\n%s", cfgText)
	}
	if !strings.Contains(cfgText, "persistent_keepalive_interval=25\n") {
		t.Fatalf("expected keepalive when endpoint present, got:\n%s", cfgText)
	}
}
