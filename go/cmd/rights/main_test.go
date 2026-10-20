package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// [STO-L3] With no configuration folder DefaultStateDir is "", and
// filepath.Join("", "admin.secret") is the working folder's admin.secret.
// The command refuses a state folder that is not absolute before it reads
// anything, as keepawake does.
func TestAdminSecretRefusesARelativeStateFolder(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "admin.secret"), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	for _, state := range []string{"", ".", "state"} {
		secret, err := adminSecret(state)
		if err == nil || !strings.Contains(err.Error(), "--state") {
			t.Fatalf("adminSecret(%q) = %q, %v; want a refusal naming --state", state, secret, err)
		}
	}
	abs := filepath.Join(work, "abs")
	if err := os.Mkdir(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(abs, "admin.secret"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if secret, err := adminSecret(abs); err != nil || secret != "kept" {
		t.Fatalf("adminSecret(%q) = %q, %v", abs, secret, err)
	}
}
