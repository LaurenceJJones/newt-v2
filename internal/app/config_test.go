package app

import (
	"flag"
	"os"
	"testing"
)

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

func TestLoadFromEnvLoadsConnectionFields(t *testing.T) {
	t.Setenv("PANGOLIN_ENDPOINT", "wss://env.example.com")
	t.Setenv("NEWT_ID", "env-id")
	t.Setenv("NEWT_SECRET", "env-secret")
	t.Setenv("LOG_LEVEL", "debug")

	cfg := DefaultConfig()
	cfg.loadFromEnv()

	if cfg.Endpoint != "wss://env.example.com" {
		t.Fatalf("unexpected endpoint: %q", cfg.Endpoint)
	}
	if cfg.ID != "env-id" {
		t.Fatalf("unexpected id: %q", cfg.ID)
	}
	if cfg.Secret != "env-secret" {
		t.Fatalf("unexpected secret: %q", cfg.Secret)
	}
	if cfg.LogLevel != "DEBUG" {
		t.Fatalf("unexpected log level: %q", cfg.LogLevel)
	}
}

func TestParseFlagsOverridesEnvironmentValues(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	fs := flag.NewFlagSet(oldArgs[0], flag.ContinueOnError)
	os.Args = []string{
		oldArgs[0],
		"--endpoint", "wss://flag.example.com",
		"--id", "flag-id",
		"--secret", "flag-secret",
		"--port", "4242",
	}

	cfg := DefaultConfig()
	cfg.Endpoint = "wss://env.example.com"
	cfg.ID = "env-id"
	cfg.Secret = "env-secret"
	cfg.Port = 1234

	cfg.parseFlagsWithSet(fs)

	if cfg.Endpoint != "wss://flag.example.com" {
		t.Fatalf("unexpected endpoint: %q", cfg.Endpoint)
	}
	if cfg.ID != "flag-id" {
		t.Fatalf("unexpected id: %q", cfg.ID)
	}
	if cfg.Secret != "flag-secret" {
		t.Fatalf("unexpected secret: %q", cfg.Secret)
	}
	if cfg.Port != 4242 {
		t.Fatalf("unexpected port: %d", cfg.Port)
	}
}
