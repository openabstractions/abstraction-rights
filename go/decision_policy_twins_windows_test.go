//go:build windows

package rights

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// A rule names one program as NTFS names files: a twin whose name differs
// by a KELVIN SIGN or a LONG S, which Unicode case folding would take for
// the same name, is another program. A permit for one never decides the
// other, and a load never merges their rules.
func TestRulesNeverMatchATwinProgram(t *testing.T) {
	dir := t.TempDir()
	for _, pair := range [][2]string{{"link", "linK"}, {"xs", "xſ"}} {
		real, twin := filepath.Join(dir, pair[0]+".exe"), filepath.Join(dir, pair[1]+".exe")
		for _, p := range []string{real, twin} {
			if err := os.WriteFile(p, []byte(p), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		realSubject := wire.Subject{Account: "test-account", Program: real}
		twinSubject := wire.Subject{Account: "test-account", Program: twin}

		p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), []string{decisionAction})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Set(realSubject, decisionAction, "content", true); err != nil {
			t.Fatal(err)
		}
		if d := p.Decide(twinSubject, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
			t.Fatalf("a permit for %q decided %q: %v, want not_granted", real, twin, d.Outcome)
		}
		if read := p.ReadRule(twinSubject, decisionAction, "content"); read.Outcome != wire.RuleReadOutcomeUnknown {
			t.Fatalf("ReadRule for %q found the rule of %q: %+v", twin, real, read)
		}

		path := filepath.Join(t.TempDir(), "decisions.json")
		now := time.Now()
		writeDecisionState(t, path, storedRule(t, real, "content", true, now), storedRule(t, twin, "content", false, now))
		loaded, err := LoadDecisionPolicy(path, []string{decisionAction})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := loaded.OperatorSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Rules) != 2 {
			t.Fatalf("a load merged %q and %q: %+v", real, twin, snapshot.Rules)
		}
		if d := loaded.Decide(realSubject, decisionAction, "content"); d.Outcome != wire.DecisionOutcomePermitted {
			t.Fatalf("%q beside its twin's deny: %v, want permitted", real, d.Outcome)
		}
		if d := loaded.Decide(twinSubject, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
			t.Fatalf("%q with its own deny: %v, want denied", twin, d.Outcome)
		}
	}
}
