package authdaemon

import (
	"log/slog"
	"path/filepath"
	"testing"

	pkglogger "github.com/fosrl/newt/pkg/logger"
)

func testAuthLogger() *slog.Logger { return pkglogger.Discard() }

func TestNewServerRequiresKeyWhenHTTPSEnabled(t *testing.T) {
	_, err := NewServer(Config{
		DisableHTTPS:       false,
		ListenAddr:         "127.0.0.1:9443",
		CACertPath:         "/tmp/ca.pem",
		PrincipalsFilePath: "/tmp/principals",
	}, nil, testAuthLogger())
	if err == nil {
		t.Fatal("expected error when HTTPS is enabled without a pre-shared key")
	}
}

func TestNewServerAllowsEmbeddedModeWithoutHTTPS(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(Config{
		DisableHTTPS:       true,
		CACertPath:         filepath.Join(dir, "ca.pem"),
		PrincipalsFilePath: filepath.Join(dir, "principals.json"),
	}, nil, testAuthLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if srv == nil {
		t.Fatal("expected server instance")
	}
}
