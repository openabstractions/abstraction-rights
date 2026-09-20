package rights

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// A host that required its decision state reads a removed file as an outage:
// decisions are unavailable and edits refuse, so a removed file never becomes
// an empty policy. Restoring the file restores the same decisions.
func TestStateRequiredMakesAMissingFileAnOutage(t *testing.T) {
	const action = "abstraction.config/user.replace"
	path := filepath.Join(t.TempDir(), "decisions.json")
	policy, err := LoadDecisionPolicy(path, []string{action})
	if err != nil {
		t.Fatal(err)
	}
	subject := wire.Subject{Account: "S-1-5-21-1-2-3-1001", Program: filepath.Join(t.TempDir(), "app")}
	if d := policy.Decide(subject, action, "editor"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("absent file without StateRequired: %+v", d)
	}
	if err := policy.Set(subject, action, "editor", true); err != nil {
		t.Fatal(err)
	}
	policy.StateRequired = true
	if d := policy.Decide(subject, action, "editor"); d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatalf("present file: %+v", d)
	}
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if d := policy.Decide(subject, action, "editor"); d.Outcome != wire.DecisionOutcomeUnavailable || d.PolicyRevision != "" {
		t.Fatalf("missing file: %+v", d)
	}
	if err := policy.Set(subject, action, "editor", true); !errors.Is(err, ErrDecisionStateMissing) {
		t.Fatalf("edit of a missing file: %v", err)
	}
	if err := policy.RegisterAction("example/other"); !errors.Is(err, ErrDecisionStateMissing) {
		t.Fatalf("registration into a missing file: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused edit created the file: %v", err)
	}
	if err := policy.Require(context.Background(), nil, action, "editor"); err == nil {
		t.Fatal("Require permitted a caller without Program proof")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := policy.Require(canceled, nil, action, "editor"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Require after cancellation: %v", err)
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	if d := policy.Decide(subject, action, "editor"); d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatalf("restored file: %+v", d)
	}
}
