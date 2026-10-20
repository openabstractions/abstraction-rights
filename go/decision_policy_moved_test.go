package rights

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestRemoveRemoteSubjectRechecksAdmissionAfterMovedFile(t *testing.T) {
	native, err := serviceSubject()
	if err != nil {
		t.Fatal(err)
	}
	s := remoteTestSubject(native.Account, "a")
	other := otherDecisionState(t, s)
	for _, withdrawn := range []bool{false, true} {
		t.Run(fmtBool(withdrawn), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "decisions.json")
			p, err := LoadDecisionPolicy(path, []string{decisionAction})
			if err != nil {
				t.Fatal(err)
			}
			if err = p.Set(s, decisionAction, "a", true); err != nil {
				t.Fatal(err)
			}
			before, _ := p.OperatorSnapshot()
			calls, notifications := 0, 0
			p.OnChange(func() { notifications++ })
			denied := errors.New("Remove withdrawn during retry")
			v, err := p.RemoveRemoteSubjectContext(context.Background(), before.Revision, s, func() error {
				calls++
				if calls == 1 {
					return os.WriteFile(path, other, 0600)
				}
				if withdrawn {
					return denied
				}
				return nil
			})
			if withdrawn {
				if !errors.Is(err, denied) || v.Outcome != wire.PolicyEditOutcomeUnavailable || v.Revision != "" {
					t.Fatal(v, err)
				}
			} else {
				now, _ := p.OperatorSnapshot()
				if err != nil || v.Outcome != wire.PolicyEditOutcomeConflict || v.Revision != now.Revision {
					t.Fatal(v, err)
				}
			}
			data, _ := os.ReadFile(path)
			if calls != 2 || notifications != 0 || !bytes.Equal(data, other) {
				t.Fatal("retry overwrote or misreported outside state", calls, notifications)
			}
		})
	}
}

func fmtBool(v bool) string {
	if v {
		return "withdrawn"
	}
	return "stale"
}

// otherDecisionState returns a valid state file for the same seed that holds
// one rule more than the file at path will, as a writer outside the lock
// would leave it.
func otherDecisionState(t *testing.T, s wire.Subject) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "other.json")
	q, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"a", "b"} {
		if err := q.Set(s, decisionAction, resource, true); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The file store answers cas.ErrMoved when the state file changed between its
// read and its write under the lock. A conditional edit then runs again on
// the file as it is now and reads a conflict with the current revision; it
// never reports the policy unavailable, and the outside content stays.
func TestDecisionEditsRunAgainOnAFileChangedOutsideTheLock(t *testing.T) {
	s := subject(t)
	other := otherDecisionState(t, s)
	for _, edit := range []string{"rule", "action"} {
		t.Run(edit, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "decisions.json")
			p, err := LoadDecisionPolicy(path, []string{decisionAction})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Set(s, decisionAction, "a", true); err != nil {
				t.Fatal(err)
			}
			before, err := p.OperatorSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			runs := 0
			authorize := func() error {
				runs++
				if runs == 1 {
					return os.WriteFile(path, other, 0o600)
				}
				return nil
			}
			var outcome, revision string
			switch edit {
			case "rule":
				permit := true
				result, err := p.ChangeRule(before.Revision, s, decisionAction, "c", RuleEdit{Permit: &permit, By: s}, authorize)
				if err != nil {
					t.Fatalf("a moved file made the edit fail: %v", err)
				}
				outcome, revision = result.Outcome.String(), result.Revision
				if result.Outcome != wire.PolicyEditOutcomeConflict {
					t.Fatalf("edit on a moved file: %+v, want conflict", result)
				}
			case "action":
				result, err := p.EditAction(before.Revision, "owner/registered", true, s, authorize)
				if err != nil {
					t.Fatalf("a moved file made the edit fail: %v", err)
				}
				outcome, revision = result.Outcome.String(), result.Revision
				if result.Outcome != wire.ActionEditOutcomeConflict {
					t.Fatalf("edit on a moved file: %+v, want conflict", result)
				}
			}
			if runs != 2 {
				t.Fatalf("the edit ran %d times, want 2", runs)
			}
			now, err := p.OperatorSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if revision != now.Revision || revision == before.Revision {
				t.Fatalf("%s carries revision %s; the file now reads %s (before %s)", outcome, revision, now.Revision, before.Revision)
			}
			if data, _ := os.ReadFile(path); !bytes.Equal(data, other) {
				t.Fatal("the edit wrote over the outside change")
			}
		})
	}
}
