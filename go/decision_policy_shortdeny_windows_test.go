//go:build windows

package rights

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// writeDecisionState writes a state file holding rules as given, sorted by
// key, as an older runtime or a hand edit could have left it.
func writeDecisionState(t *testing.T, path string, rules ...decisionRule) {
	t.Helper()
	slices.SortFunc(rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	data, err := json.Marshal(decisionFile{Profile: DecisionProfile, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func storedRule(t *testing.T, program, resource string, permit bool, at time.Time) decisionRule {
	return decisionRule{Subject: wire.Subject{Account: "test-account", Program: program}, Action: decisionAction, Resource: resource,
		Permit: permit, SetBy: subject(t), SetAt: stamp(at)}
}

// laterProgram creates <dir>\later folder\subject.exe, reads its short alias,
// and removes the folder again: the alias names nothing until the folder is
// created again, which recreate does.
func laterProgram(t *testing.T) (long, short string, recreate func()) {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "later folder")
	long = filepath.Join(folder, "subject.exe")
	recreate = func() {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(long, []byte("subject"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	recreate()
	short, ok := shortAlias(t, long)
	if !ok {
		t.Skip("filesystem has no distinct DOS alias for this file")
	}
	if err := os.RemoveAll(folder); err != nil {
		t.Fatal(err)
	}
	return long, short, recreate
}

// A deny stored under a short spelling before its file existed (an older
// runtime stored such spellings) reads denied once the file appears, without
// a restart and after one; the restart rewrites it under the long spelling.
// A new rule under such a spelling is refused.
func TestDenyStoredUnderAShortSpellingSurvivesItsFileAppearing(t *testing.T) {
	long, short, recreate := laterProgram(t)
	path := filepath.Join(t.TempDir(), "decisions.json")
	writeDecisionState(t, path, storedRule(t, short, "content", false, time.Now()))
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	refused := p.Set(wire.Subject{Account: "test-account", Program: short}, decisionAction, "other", false)
	// The refusal names the path as far as it resolves: the missing folder
	// keeps its alias.
	missing := filepath.Base(filepath.Dir(short))
	if !errors.Is(refused, ErrUnresolvedShortName) || !strings.Contains(refused.Error(), missing) {
		t.Fatalf("a rule for an alias that names nothing: %v, want ErrUnresolvedShortName naming %q", refused, missing)
	}
	permit := true
	if edit, err := p.ChangeRule("any", wire.Subject{Account: "test-account", Program: short}, decisionAction, "other",
		RuleEdit{Permit: &permit, By: subject(t)}, func() error { return nil }); edit.Outcome != wire.PolicyEditOutcomeInvalid || !errors.Is(err, ErrUnresolvedShortName) {
		t.Fatalf("ChangeRule for an alias that names nothing: %+v %v, want invalid with ErrUnresolvedShortName", edit, err)
	}

	recreate()
	if again, ok := shortAlias(t, long); !ok || again != short {
		t.Skipf("the recreated file has the alias %q, not %q", again, short)
	}
	owner := wire.Subject{Account: "test-account", Program: long}
	if d := p.Decide(owner, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("a deny stored under %q, decided for %q once the file exists: %v, want denied", short, long, d.Outcome)
	}
	if read := p.ReadRule(owner, decisionAction, "content"); read.Outcome != wire.RuleReadOutcomeFound || read.Record.Rule.Permit {
		t.Fatalf("the stored deny read for the long spelling: %+v", read)
	}

	restarted, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	quotedLong, _ := json.Marshal(long)
	quotedShort, _ := json.Marshal(short)
	if !strings.Contains(string(data), string(quotedLong)) || strings.Contains(string(data), string(quotedShort)) {
		t.Fatalf("a restart left the short spelling in the state: %s", data)
	}
	if d := restarted.Decide(owner, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("after a restart: %v, want denied", d.Outcome)
	}
}

// Two stored rules that name one target once their spellings are canonical
// merge into one, and the deny wins, whichever spelling held it.
func TestCanonicalSpellingCollisionKeepsTheDeny(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "rule program")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(folder, "subject.exe")
	if err := os.WriteFile(long, []byte("subject"), 0o755); err != nil {
		t.Fatal(err)
	}
	short, ok := shortAlias(t, long)
	if !ok {
		t.Skip("filesystem has no distinct DOS alias for this file")
	}
	owner := wire.Subject{Account: "test-account", Program: long}
	now := time.Now()
	for _, c := range []struct {
		name          string
		denyUnder     string
		permitUnder   string
		permitIsNewer bool
	}{
		{"deny-short", short, long, true},
		{"deny-long", long, short, true},
		{"deny-newer", short, long, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "decisions.json")
			denyAt, permitAt := now, now.Add(time.Minute)
			if !c.permitIsNewer {
				denyAt, permitAt = permitAt, denyAt
			}
			writeDecisionState(t, path, storedRule(t, c.denyUnder, "content", false, denyAt), storedRule(t, c.permitUnder, "content", true, permitAt))

			// Read before any load: the decision merges in memory.
			reader := &DecisionPolicy{path: path, seed: []string{decisionAction}, native: subject(t)}
			if d := reader.Decide(owner, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
				t.Fatalf("before a load: %v, want denied", d.Outcome)
			}
			p, err := LoadDecisionPolicy(path, []string{decisionAction})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := p.OperatorSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Rules) != 1 || snapshot.Rules[0].Permit || snapshot.Rules[0].Subject != owner {
				t.Fatalf("after a load: %+v, want one deny for %q", snapshot.Rules, long)
			}
			if d := p.Decide(wire.Subject{Account: "test-account", Program: short}, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
				t.Fatalf("after a load, decided for the short spelling: %v, want denied", d.Outcome)
			}
		})
	}
}

// Windows file names are case-insensitive. A deny written for a file that
// does not exist yet, in a folder spelled with other capitals than the folder
// later created, reads denied once the file appears, without a restart, and
// installation finds it; a permit stored under a third spelling loses to it.
func TestDenyWrittenInAnotherCaseDecidesTheProgram(t *testing.T) {
	base := t.TempDir()
	typed := filepath.Join(base, "LATER FOLDER", "SUBJECT.EXE")
	created := filepath.Join(base, "later folder", "Subject.exe")
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Set(wire.Subject{Account: "test-account", Program: typed}, decisionAction, "content", false); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(created), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created, []byte("subject"), 0o755); err != nil {
		t.Fatal(err)
	}
	proven := wire.Subject{Account: "test-account", Program: created}
	if d := p.Decide(proven, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("a deny written for %q, decided for %q: %v, want denied", typed, created, d.Outcome)
	}
	read := p.ReadRule(proven, decisionAction, "content")
	if read.Outcome != wire.RuleReadOutcomeFound || read.Record.Rule.Permit {
		t.Fatalf("the deny read for %q: %+v", created, read)
	}
	// An installation writes only where ReadRule finds no rule; a conditional
	// permit at the current revision would replace the deny, so none is
	// attempted, and an unconditional edit of the target names the same rule.
	permit := true
	if edit, err := p.ChangeRule(read.Revision, wire.Subject{Account: "test-account", Program: strings.ToLower(created)}, decisionAction, "content",
		RuleEdit{Permit: &permit, By: subject(t)}, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("edit of the target under a lower-case spelling: %+v %v", edit, err)
	}
	snapshot, err := p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Rules) != 1 {
		t.Fatalf("an edit under another case left %d rules: %+v, want the one rule replaced", len(snapshot.Rules), snapshot.Rules)
	}

	// A deny and a permit stored under spellings that differ only in case
	// merge at load, and the deny wins.
	collided := filepath.Join(t.TempDir(), "decisions.json")
	writeDecisionState(t, collided, storedRule(t, typed, "content", false, time.Now()), storedRule(t, created, "content", true, time.Now().Add(time.Minute)))
	reader := &DecisionPolicy{path: collided, seed: []string{decisionAction}, native: subject(t)}
	if d := reader.Decide(proven, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("case variants before a load: %v, want denied", d.Outcome)
	}
	loaded, err := LoadDecisionPolicy(collided, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := loaded.OperatorSnapshot(); err != nil || len(snapshot.Rules) != 1 || snapshot.Rules[0].Permit {
		t.Fatalf("case variants after a load: %+v %v, want one deny", snapshot.Rules, err)
	}
}
