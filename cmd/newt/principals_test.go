package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPrincipalsCmdPrintsPrincipals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "principals.json")
	if err := os.WriteFile(path, []byte(`{"alice":["alice","nice-id"]}`), 0o644); err != nil {
		t.Fatalf("write principals: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := runPrincipalsCmd([]string{"--principals-file", path, "--username", "alice"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run principals: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	if got != "alice\nnice-id" {
		t.Fatalf("unexpected output: %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", stderr.String())
	}
}

func TestRunPrincipalsCmdRequiresUsername(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runPrincipalsCmd(nil, &stdout, &stderr)
	if err == nil || err.Error() != "username is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}
