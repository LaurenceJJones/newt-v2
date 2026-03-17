package app

import "testing"

func TestValidateRequiresAuthDaemonKeyWhenAddrConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Endpoint = "wss://example.com"
	cfg.ID = "newt-id"
	cfg.Secret = "secret"
	cfg.AuthDaemonEnabled = true
	cfg.AuthDaemonAddr = "127.0.0.1:9443"
	cfg.AuthDaemonKey = ""

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when auth daemon address is set without key")
	}
}
