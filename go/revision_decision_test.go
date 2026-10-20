package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoveRemoteSubjectCommitOrderAndCancellation(t *testing.T) {
	p, _ := testSelectorPolicy(t)
	actor := p.native
	s := remoteTestSubject(actor.Account, "a")
	if err := p.Set(s, selectorUse, "legacy", true); err != nil {
		t.Fatal(err)
	}
	setRemovalSelector(t, p, s, testSelection(selectorUse, "alpha"), true)
	if err := p.EnableRevisionDecisions("remove-peer/v1"); err != nil {
		t.Fatal(err)
	}
	before, revision, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.path)
	ctx, cancel := context.WithCancel(context.Background())
	v, err := p.RemoveRemoteSubjectContext(ctx, revision, s, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || v.Outcome != wire.PolicyEditOutcomeUnavailable {
		t.Fatal("cancel before commit", v, err)
	}
	unchanged, _ := os.ReadFile(p.path)
	if !bytes.Equal(data, unchanged) {
		t.Fatal("cancelled commit partially removed rules")
	}
	v, err = p.RemoveRemoteSubjectContext(context.Background(), revision, s, func() error { return nil })
	after, current, readErr := p.readDecision()
	if err != nil || readErr != nil || v.Outcome != wire.PolicyEditOutcomeApplied || v.Revision != current || len(after.Rules) != 0 || len(after.SelectorRules) != 0 || after.Order.Epoch != before.Order.Epoch || after.Order.Sequence != before.Order.Sequence+1 {
		t.Fatal(v, err, readErr, before.Order, after.Order)
	}
	// Exhaustion is a real checkedChange commit refusal, affecting neither family.
	if err = p.Set(s, selectorUse, "again", true); err != nil {
		t.Fatal(err)
	}
	setRemovalSelector(t, p, s, testSelection(selectorUse, "beta"), true)
	f, _, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	f.Order.Sequence = math.MaxInt64
	exhausted, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p.path, exhausted, 0600); err != nil {
		t.Fatal(err)
	}
	_, revision, err = p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	v, err = p.RemoveRemoteSubjectContext(context.Background(), revision, s, func() error { return nil })
	unchanged, _ = os.ReadFile(p.path)
	if err == nil || v.Outcome != wire.PolicyEditOutcomeUnavailable || !bytes.Equal(exhausted, unchanged) {
		t.Fatal("failed commit changed state", v, err)
	}
}

func TestRevisionFenceOrderRestorationRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, e := LoadDecisionPolicy(path, []string{"test/read"})
	if e != nil {
		t.Fatal(e)
	}
	before, e := p.OperatorSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("old read created state", e)
	}
	subject := wire.Subject{Account: p.native.Account, Program: "remote:" + strings.Repeat("a", 64)}
	decide := func(min string) wire.RevisionDecision {
		return p.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", min)
	}
	if d := decide(""); d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal(d)
	}
	if e = p.EnableRevisionDecisions("test-owner/v1"); e != nil {
		t.Fatal(e)
	}
	first := decide("")
	if first.ObservedRevision == "" || first.Decision.PolicyRevision != before.Revision {
		t.Fatal(first, before)
	}
	if e = p.ConfigureDefaults("", nil, nil); e == nil {
		t.Fatal("configuration was mutable")
	}
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.change(func(data []byte) ([]byte, error) { return data, nil }); e != nil {
		t.Fatal(e)
	}
	if d := decide(first.ObservedRevision); d.ObservedRevision != first.ObservedRevision {
		t.Fatal("no-op minted commit", d)
	}
	// A real change followed by semantic restoration retains the content hash,
	// while its durable observation advances twice.
	if e = p.change(func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		f.AppliedOperatorAnswers = []string{strings.Repeat("a", 32)}
		return json.Marshal(f)
	}); e != nil {
		t.Fatal(e)
	}
	if e = p.change(func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		f.AppliedOperatorAnswers = nil
		return json.Marshal(f)
	}); e != nil {
		t.Fatal(e)
	}
	restored := decide(first.ObservedRevision)
	if restored.Decision.PolicyRevision != first.Decision.PolicyRevision || restored.ObservedRevision == first.ObservedRevision {
		t.Fatal(restored, first)
	}
	q, e := LoadDecisionPolicy(path, []string{"test/read"})
	if e != nil {
		t.Fatal(e)
	}
	if e = q.EnableRevisionDecisions("test-owner/v1"); e != nil {
		t.Fatal(e)
	}
	if d := q.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", restored.ObservedRevision); d.ObservedRevision != restored.ObservedRevision {
		t.Fatal(d)
	}
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	if d := decide(restored.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomeUnavailable || d.ObservedRevision != "" {
		t.Fatal("rollback admitted", d)
	}
	if d := decide(strings.Repeat("x", 129)); d.Decision.Outcome != wire.DecisionOutcomeInvalid {
		t.Fatal(d)
	}
	if e = q.EnableRevisionDecisions("different/v1"); e == nil {
		t.Fatal("changed configuration admitted")
	}
	p.native.Account = "changed-owner"
	if d := decide(""); d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal("changed native account admitted", d)
	}
}

func TestRevisionLegacyMigrationAndConfiguration(t *testing.T) {
	for v := 2; v <= 7; v++ {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			f := decisionFile{Profile: fmt.Sprintf("rights-decisions@%d", v)}
			data, _ := json.Marshal(f)
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			p, e := LoadDecisionPolicy(path, []string{"test/read"})
			if e != nil {
				t.Fatal(e)
			}
			before, _ := p.OperatorSnapshot()
			if e = p.EnableRevisionDecisions("owner/v1"); e != nil {
				t.Fatal(e)
			}
			after, _ := p.OperatorSnapshot()
			if (before.Revision == after.Revision) != (v == 7) {
				t.Fatalf("profile%d migration: %s -> %s", v, before.Revision, after.Revision)
			}
			subject := wire.Subject{Account: p.native.Account, Program: "remote:" + strings.Repeat("a", 64)}
			observed := p.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", "")
			q, e := LoadDecisionPolicy(path, []string{"test/read"})
			if e != nil {
				t.Fatal(e)
			}
			if e = q.EnableRevisionDecisions("owner/v2"); e != nil {
				t.Fatal(e)
			}
			if d := q.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", observed.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
				t.Fatal(d)
			}
		})
	}
}

func TestRevisionCASRetryErrorsAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	p, e := LoadDecisionPolicy(path, []string{decisionAction})
	if e != nil {
		t.Fatal(e)
	}
	if e = p.EnableRevisionDecisions("owner/v1"); e != nil {
		t.Fatal(e)
	}
	read := func() decisionFile {
		f, _, e := p.readDecision()
		if e != nil {
			t.Fatal(e)
		}
		return f
	}
	initial := read()
	sentinel := errors.New("refused edit")
	if e = p.change(func([]byte) ([]byte, error) { return nil, sentinel }); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if read().Order.Sequence != initial.Order.Sequence {
		t.Fatal("failed edit minted commit")
	}
	runs := 0
	if e = p.change(func(data []byte) ([]byte, error) {
		runs++
		if runs == 1 {
			f, _ := p.decodeDecision(data)
			f.Order = &decisionOrder{Epoch: f.Order.Epoch, Sequence: 5}
			outside, _ := json.Marshal(f)
			if e := os.WriteFile(path, outside, 0600); e != nil {
				return nil, e
			}
		}
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		f.AppliedOperatorAnswers = []string{strings.Repeat("a", 32)}
		return json.Marshal(f)
	}); e != nil {
		t.Fatal(e)
	}
	if runs != 2 || read().Order.Sequence != 6 {
		t.Fatal("retry did not use committed head", runs, read().Order)
	}
	now := time.Now().UTC()
	p.Clock = func() time.Time { return now }
	target := wire.Subject{Account: p.native.Account, Program: "remote:" + strings.Repeat("a", 64)}
	snapshot, _ := p.OperatorSnapshot()
	permit := true
	result, e := p.ChangeRule(snapshot.Revision, target, decisionAction, "item", RuleEdit{Permit: &permit, By: p.native, TTL: time.Minute}, func() error { return nil })
	if e != nil || result.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(result, e)
	}
	first := p.DecideForAtLeastRevisionContext(context.Background(), target, decisionAction, "item", "")
	now = now.Add(2 * time.Minute)
	after := p.DecideForAtLeastRevisionContext(context.Background(), target, decisionAction, "item", first.ObservedRevision)
	if first.Decision.Outcome != wire.DecisionOutcomePermitted || after.Decision.Outcome != wire.DecisionOutcomeNotGranted || first.ObservedRevision != after.ObservedRevision {
		t.Fatal(first, after)
	}
}

func TestRevisionMinimumTenRefusesRollbackFive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	p, e := LoadDecisionPolicy(path, []string{"test/read"})
	if e != nil {
		t.Fatal(e)
	}
	if e = p.EnableRevisionDecisions("owner/v1"); e != nil {
		t.Fatal(e)
	}
	f, _, e := p.readDecision()
	if e != nil {
		t.Fatal(e)
	}
	f.Order = &decisionOrder{Epoch: f.Order.Epoch, Sequence: 10}
	data, _ := json.Marshal(f)
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	subject := wire.Subject{Account: p.native.Account, Program: "remote:" + strings.Repeat("a", 64)}
	observed := p.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", "")
	f.Order = &decisionOrder{Epoch: f.Order.Epoch, Sequence: 5}
	data, _ = json.Marshal(f)
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	q, e := LoadDecisionPolicy(path, []string{"test/read"})
	if e != nil {
		t.Fatal(e)
	}
	if e = q.EnableRevisionDecisions("owner/v1"); e != nil {
		t.Fatal(e)
	}
	d := q.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", observed.ObservedRevision)
	if d.Decision.Outcome != wire.DecisionOutcomeUnavailable || d.ObservedRevision != "" {
		t.Fatal(d)
	}
	// A different durable epoch remains incomparable, even with a high sequence.
	f.Order = &decisionOrder{Epoch: strings.Repeat("b", 32), Sequence: 100}
	data, _ = json.Marshal(f)
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	d = q.DecideForAtLeastRevisionContext(context.Background(), subject, "test/read", "item", observed.ObservedRevision)
	if d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal(d)
	}
}

func TestRevisionOrderParserAndOverflow(t *testing.T) {
	good := revisionObservation(&decisionOrder{Epoch: strings.Repeat("a", 32), Sequence: 10}, strings.Repeat("b", 64))
	if _, _, n, ok := parseRevisionObservation(good); !ok || n != 10 {
		t.Fatal(good)
	}
	for _, s := range []string{good + "0x", strings.Replace(good, ".10", ".010", 1), strings.Replace(good, ".10", ".-1", 1), strings.ToUpper(good), strings.Repeat("x", 129)} {
		if _, _, _, ok := parseRevisionObservation(s); ok {
			t.Fatal(s)
		}
	}
	p, e := LoadDecisionPolicy(filepath.Join(t.TempDir(), "state"), []string{"test/read"})
	if e != nil {
		t.Fatal(e)
	}
	old := decisionFile{Profile: orderedDecisionProfile, Order: &decisionOrder{Epoch: strings.Repeat("a", 32), Sequence: math.MaxInt64}}
	data, _ := json.Marshal(old)
	old.Profile = DecisionProfile
	old.AppliedOperatorAnswers = []string{strings.Repeat("a", 64)}
	next, _ := json.Marshal(old)
	if _, e = p.orderChange(data, next); e == nil {
		t.Fatal("overflow admitted")
	}
}

func TestRevisionTypedOperationUsesOneStateAndClock(t *testing.T) {
	p, subject := testSelectorPolicy(t)
	setTestSelector(t, p, subject, testSelection(selectorUse, "alpha"), true)
	if err := p.Set(subject, selectorUse, "name:alpha", true); err != nil {
		t.Fatal(err)
	}
	if err := p.EnableRevisionDecisions("typed-revision/v1"); err != nil {
		t.Fatal(err)
	}
	concrete := wire.ConcreteResource{Permission: testSelection(selectorUse, "alpha").Permission, Target: testTarget("alpha")}
	req := wire.LegacyOperationRequest{LegacyAction: selectorUse, LegacyResource: "name:alpha", ConcreteOperation: &concrete}
	decide := func(min string) wire.RevisionDecision {
		return p.CheckLegacyOperationAtLeastRevisionContext(context.Background(), subject, req, min)
	}
	first := decide("")
	if first.Decision.Outcome != wire.DecisionOutcomePermitted || first.ObservedRevision == "" {
		t.Fatal(first)
	}
	old, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	setTestSelector(t, p, subject, testSelection(selectorUse, "alpha"), false)
	blocked, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	later := decide(first.ObservedRevision)
	if later.Decision.Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("typed Block lost to legacy Permit", later)
	}
	if err := os.WriteFile(p.path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if d := decide(later.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal("rollback", d)
	}
	calls := 0
	p.Clock = func() time.Time {
		calls++
		if err := os.WriteFile(p.path, blocked, 0600); err != nil {
			t.Fatal(err)
		}
		return time.Now()
	}
	// A concurrent publication at the clock boundary cannot change this read.
	if d := decide(first.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomePermitted || d.ObservedRevision != first.ObservedRevision || calls != 1 {
		t.Fatal("split state or clock", d, calls)
	}
	p.Clock = nil
	if d := decide(first.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("next read missed Block", d)
	}
	bad := req
	bad.ConcreteOperation = &wire.ConcreteResource{}
	if d := p.CheckLegacyOperationAtLeastRevisionContext(context.Background(), subject, bad, first.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomeInvalid {
		t.Fatal("unknown typed target", d)
	}
	if d := decide("rf1." + strings.Repeat("0", 32) + "." + p.revisionConfigurationDigest + ".0"); d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal("incomparable", d)
	}
	if d := decide("malformed"); d.Decision.Outcome != wire.DecisionOutcomeInvalid {
		t.Fatal(d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d := p.CheckLegacyOperationAtLeastRevisionContext(ctx, subject, req, first.ObservedRevision); d.Decision.Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal("cancelled read", d)
	}
}
