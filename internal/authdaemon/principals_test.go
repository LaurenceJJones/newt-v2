package authdaemon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGetPrincipalsReturnsUserEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "principals.json")
	if err := os.WriteFile(path, []byte(`{"alice":["alice","nice-id"],"bob":["bob"]}`), 0o644); err != nil {
		t.Fatalf("write principals: %v", err)
	}

	got, err := GetPrincipals(path, "alice")
	if err != nil {
		t.Fatalf("get principals: %v", err)
	}

	want := []string{"alice", "nice-id"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected principals: got=%v want=%v", got, want)
	}
}

func TestGetPrincipalsReturnsEmptyListForUnknownUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "principals.json")
	if err := os.WriteFile(path, []byte(`{"alice":["alice"]}`), 0o644); err != nil {
		t.Fatalf("write principals: %v", err)
	}

	got, err := GetPrincipals(path, "bob")
	if err != nil {
		t.Fatalf("get principals: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no principals, got %v", got)
	}
}
