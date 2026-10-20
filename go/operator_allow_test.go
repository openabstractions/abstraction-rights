package rights

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	cas "github.com/openabstractions/abstraction-cas/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

const operatorQ1 = "11111111111111111111111111111111"
const operatorQ2 = "22222222222222222222222222222222"

func TestOperatorAllowProofSurvivesRemovalAndLostReply(t *testing.T) {
	f := newMetaFixture(t)
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	permit := true
	rules := pairedBatch(f)
	// Discard the reply: the committed file is the sole recovery evidence.
	_, err := f.p.ApplyFirstUseAllow(context.Background(), f.revision(t), rules, RuleEdit{Permit: &permit, By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.p.path)
	if err != nil {
		t.Fatal(err)
	}
	var committed decisionFile
	if err := json.Unmarshal(data, &committed); err != nil || len(committed.Rules) != 2 || !slices.Contains(committed.AppliedOperatorAnswers, operatorQ1) {
		t.Fatalf("complete permits and receipt: %+v %v", committed, err)
	}
	if err := f.p.Revoke(f.appA, decisionAction, "output:image"); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadDecisionPolicy(f.p.path, f.p.seed)
	if err != nil {
		t.Fatal(err)
	}
	if yes, err := restarted.AppliedFirstUseAllow(operatorQ1); err != nil || !yes {
		t.Fatalf("revoked proof after restart: %v %v", yes, err)
	}
	before, _ := restarted.OperatorSnapshot()
	edit, err := restarted.ApplyFirstUseAllow(context.Background(), before.Revision, rules, RuleEdit{Permit: &permit, By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict || edit.Revision != before.Revision || restarted.Decide(f.appA, decisionAction, "output:image").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("completed replay restored rights: %+v %v", edit, err)
	}
}

func TestOperatorAllowFailedAndReceiptOnlyEdits(t *testing.T) {
	f := newMetaFixture(t)
	permit := true
	rules := []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "output:image", Permit: true}}
	before := f.revision(t)
	for _, expected := range []string{"stale", before} {
		edit, err := f.p.ApplyFirstUseAllow(context.Background(), expected, rules, RuleEdit{Permit: &permit, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error {
			if expected == before {
				return errors.New("withdrawn")
			}
			return nil
		})
		if edit.Outcome == wire.PolicyEditOutcomeApplied || f.revision(t) != before {
			t.Fatalf("failed edit wrote state: %+v %v", edit, err)
		}
	}
	if err := f.p.Set(f.appA, decisionAction, "output:image", true); err != nil {
		t.Fatal(err)
	}
	before = f.revision(t)
	edit, err := f.p.ApplyFirstUseAllow(context.Background(), before, rules, RuleEdit{Permit: &permit, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || edit.Revision == before {
		t.Fatalf("first receipt-only Apply: %+v %v", edit, err)
	}
	before = edit.Revision
	ordinary, err := f.p.ChangeRules(before, rules, RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil })
	if err != nil || ordinary.Revision != before {
		t.Fatalf("ordinary no-op changed revision: %+v %v", ordinary, err)
	}
}

func TestOperatorAllowRightsLockWaitIsBounded(t *testing.T) {
	f := newMetaFixture(t)
	before := f.revision(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- cas.ChangeLimit(f.p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) { close(entered); <-release; return data, nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	permit := true
	rules := []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "output:image", Permit: true}}
	edit, err := f.p.ApplyFirstUseAllow(ctx, before, rules, RuleEdit{Permit: &permit, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { return ctx.Err() })
	close(release)
	if lockErr := <-done; lockErr != nil {
		t.Fatal(lockErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) || edit.Outcome != wire.PolicyEditOutcomeUnavailable || f.revision(t) != before {
		t.Fatalf("late rights effect after cancellation: %+v %v", edit, err)
	}
}

func TestOperatorAllowOldProfilesAndBoundedOrphanPruning(t *testing.T) {
	for _, profile := range []string{previousDecisionProfile, answerIdentityDecisionProfile} {
		t.Run(profile, func(t *testing.T) {
			f := newMetaFixture(t)
			old, _ := json.Marshal(decisionFile{Profile: profile})
			if err := os.WriteFile(f.p.path, old, 0600); err != nil {
				t.Fatal(err)
			}
			p, err := LoadDecisionPolicy(f.p.path, f.p.seed)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(f.p.path)
			if string(after) != string(old) {
				t.Fatal("canonical old profile was rewritten on read")
			}
			if err := p.Set(f.appA, decisionAction, "output:image", true); err != nil {
				t.Fatal(err)
			}
			after, _ = os.ReadFile(f.p.path)
			if !containsProfile(after, DecisionProfile) {
				t.Fatal("real write did not migrate")
			}
		})
	}
	f := newMetaFixture(t)
	state := decisionFile{Profile: DecisionProfile}
	for i := 0; i < MaxAppliedOperatorAnswers; i++ {
		state.AppliedOperatorAnswers = append(state.AppliedOperatorAnswers, fmt.Sprintf("%032x", i+1))
	}
	old := state.AppliedOperatorAnswers[0]
	data, _ := json.Marshal(state)
	if err := os.WriteFile(f.p.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	permit := true
	rules := []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "output:image", Permit: true}}
	edit, err := f.p.ApplyFirstUseAllow(context.Background(), f.revision(t), rules, RuleEdit{Permit: &permit, By: f.panel}, operatorQ2, []string{old, operatorQ2}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("orphan pruning: %+v %v", edit, err)
	}
	fresh, _, err := f.p.readDecision()
	if err != nil || len(fresh.AppliedOperatorAnswers) != 2 || !slices.Contains(fresh.AppliedOperatorAnswers, old) {
		t.Fatalf("retained proof evicted: %+v %v", fresh, err)
	}
	for _, bad := range []decisionFile{{Profile: answerIdentityDecisionProfile, AppliedOperatorAnswers: []string{operatorQ1}}, {Profile: DecisionProfile, AppliedOperatorAnswers: []string{operatorQ1, operatorQ1}}, {Profile: DecisionProfile, AppliedOperatorAnswers: []string{"bad"}}} {
		data, _ := json.Marshal(bad)
		if _, err := f.p.decodeDecision(data); err == nil {
			t.Fatalf("invalid proof accepted: %+v", bad)
		}
	}
}

func TestOperatorAllowEveryRightsWriterPreservesProof(t *testing.T) {
	f := newMetaFixture(t)
	permit := true
	rule := []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "output:image", Permit: true}}
	if _, err := f.p.ApplyFirstUseAllow(context.Background(), f.revision(t), rule, RuleEdit{Permit: &permit, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		if yes, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || !yes {
			t.Fatalf("writer lost proof: %v %v", yes, err)
		}
	}
	if err := f.p.Revoke(f.appA, decisionAction, "output:image"); err != nil {
		t.Fatal(err)
	}
	check()
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err := f.p.EditAction(f.revision(t), pairedWrite, false, f.panel, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	check()
	f.enroll(t, MetaRuleLapse)
	check()
	if _, err := f.p.ChangeRulesUnderAnswer(f.holder, f.appA, []string{decisionAction}, "output:image", "answer", "delegated", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err := f.p.RevokeAnswerPermits(f.revision(t), f.holder, f.appA, []string{decisionAction}, "output:image", "delegated", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err := f.p.StopAnswerer(f.revision(t), f.holder, true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	check()
	if err := f.p.canonicalizeState(); err != nil {
		t.Fatal(err)
	}
	check()
}
