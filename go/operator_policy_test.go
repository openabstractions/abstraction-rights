package rights

import (
	"bytes"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOperatorPolicyConcurrentRevisionAndReconciliation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t)
	initial, err := p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	authorize := func() error { return nil }
	noop, err := p.EditRule(initial.Revision, s, decisionAction, "x", nil, authorize)
	if err != nil || noop.Outcome != "applied" || noop.Revision != initial.Revision || noop.Current != nil {
		t.Fatal(noop, err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no-op created file", err)
	}
	results := make(chan wire.PolicyEdit, 2)
	var workers sync.WaitGroup
	for _, value := range []bool{true, false} {
		workers.Add(1)
		go func(value bool) {
			defer workers.Done()
			r, e := p.EditRule(initial.Revision, s, decisionAction, "x", &value, authorize)
			if e != nil {
				t.Error(e)
			}
			results <- r
		}(value)
	}
	workers.Wait()
	close(results)
	applied, conflict := 0, 0
	var current wire.PolicyEdit
	for r := range results {
		switch r.Outcome {
		case "applied":
			applied++
			current = r
		case "conflict":
			conflict++
		default:
			t.Fatal(r)
		}
	}
	if applied != 1 || conflict != 1 || current.Current == nil {
		t.Fatal(applied, conflict, current)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.EditRule(initial.Revision, s, decisionAction, "x", &current.Current.Permit, authorize)
	if err != nil || retry.Outcome != "conflict" || retry.Revision != current.Revision || *retry.Current != *current.Current {
		t.Fatal("uncertain retry overwrote", retry, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("conflict wrote", err)
	}
	same, err := reopened.EditRule(current.Revision, s, decisionAction, "x", &current.Current.Permit, authorize)
	if err != nil || same.Outcome != "applied" || same.Revision != current.Revision {
		t.Fatal(same, err)
	}
	revoked, err := reopened.EditRule(current.Revision, s, decisionAction, "x", nil, authorize)
	if err != nil || revoked.Outcome != "applied" || revoked.Current != nil {
		t.Fatal(revoked, err)
	}
	if d := reopened.Decide(s, decisionAction, "x"); d.Outcome != "not_granted" || d.PolicyRevision != revoked.Revision {
		t.Fatal(d)
	}
}
func TestOperatorPolicyRejectsMalformedAndUnavailableWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := p.OperatorSnapshot()
	s := subject(t)
	permit := true
	invalid, err := p.EditRule(snapshot.Revision, s, "not-in-catalog", "x", &permit, func() error { return nil })
	if err != nil || invalid.Outcome != "invalid" {
		t.Fatal(invalid, err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid edit created file", err)
	}
	for _, data := range [][]byte{[]byte(`{"bad":`), bytes.Repeat([]byte("x"), MaxDecisionBytes+1)} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = p.OperatorSnapshot(); err == nil {
			t.Fatal("corrupt policy appeared valid")
		}
		r, err := p.EditRule(snapshot.Revision, s, decisionAction, "x", &permit, func() error { return nil })
		if err == nil || r.Outcome != "unavailable" || r.Revision != "" || r.Current != nil {
			t.Fatal(r, err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, data) {
			t.Fatal("bad state changed", err)
		}
	}
}
