//go:build windows

package rights

import (
	"os"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// RIGHTS-O14: the explanation matches the program's own rule by program
// identity, as the decision does: a Block saved for the long spelling is the
// own rule an 8.3 alias of the same file reads, over the default.
func TestExplainForRecognizesAShortAliasRule(t *testing.T) {
	spaced := filepath.Join(t.TempDir(), "rule program")
	if err := os.Mkdir(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(spaced, "subject.exe")
	if err := os.WriteFile(long, []byte("subject"), 0o755); err != nil {
		t.Fatal(err)
	}
	short, ok := shortAlias(t, long)
	if !ok {
		t.Skip("filesystem has no distinct DOS alias for this file")
	}
	p := defaultsPolicy(t, filepath.Join(t.TempDir(), "decisions.json"), scriptHost(t))
	account := subject(t).Account
	if err := p.Set(wire.Subject{Account: account, Program: long}, ActionJobSubmit, ResourceDownloadJobs, false); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, wire.Subject{Account: account, Program: short}, ActionJobSubmit, ResourceDownloadJobs),
		wire.DecisionOutcomeDenied, wire.DecisionSourceOwnRule, "")
}
