package rights

import (
	"errors"
	"os"
	"testing"

	"github.com/openabstractions/abstraction-identity/listen"
)

// The rights service keeps its policy and admin secret only in an absolute
// state root of this account; without one it refuses to start, and nothing
// lands in the working folder or the temporary directory (storage STO-L3,
// the 0.8.0 plan's paths M8).
func TestStartRefusesWithoutAnAbsoluteStateRoot(t *testing.T) {
	if err := listen.CanEver(endpoint(t, t.TempDir(), "rights"), listen.Program); err != nil {
		t.Skip(err)
	}
	work := t.TempDir()
	t.Chdir(work)
	for _, state := range []string{"", "state"} {
		s, err := Start(endpoint(t, t.TempDir(), "rights"), state, &person{})
		if err == nil {
			s.Close()
			t.Fatalf("Start with state %q started", state)
		}
		if !errors.Is(err, ErrNoStateRoot) {
			t.Fatalf("Start with state %q: %v, want ErrNoStateRoot", state, err)
		}
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("a refused Start wrote into the working folder: %v", entries)
	}
}

// With no configuration folder for the account, the default state folder is
// empty, never a folder in the temporary directory.
func TestDefaultStateDirNeverFallsBackToTheTemporaryDirectory(t *testing.T) {
	t.Setenv("APPDATA", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("this platform answers a configuration folder with none of its variables set")
	}
	if d := DefaultStateDir(); d != "" {
		t.Fatalf("DefaultStateDir() = %q, want none", d)
	}
}
