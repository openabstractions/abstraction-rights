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

func legacyCompleteFixture(t *testing.T) (*metaFixture, wire.PermissionEffect) {
	t.Helper()
	f := newMetaFixture(t)
	effect := wire.PermissionEffect{Subject: f.appA}
	var definitions []wire.PermissionDefinition
	for _, action := range []string{"example/one", "example/three", "example/two"} {
		d := testDefinition()
		d.Action = action
		definitions = append(definitions, d)
		if err := f.p.RegisterAction(action); err != nil {
			t.Fatal(err)
		}
		effect.Selections = append(effect.Selections, wire.PermissionSelection{Permission: wire.PermissionKey{Action: action, ResourceProfile: LegacyExactResourceProfile}, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: []byte(`"app:editor"`)}})
	}
	var err error
	f.p.Definitions, err = NewDefinitionCatalog(definitions, testProfiles())
	if err != nil {
		t.Fatal(err)
	}
	return f, effect
}

func TestLegacyCompleteEffectAtomicApplyCurrentAndUndo(t *testing.T) {
	f, effect := legacyCompleteFixture(t)
	permit := true
	edit, err := f.p.ApplyLegacyPermissionEffect(t.Context(), f.revision(t), effect, RuleEdit{Permit: &permit, By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || len(edit.Current) != 3 {
		t.Fatal(edit, err)
	}
	for _, row := range edit.Current {
		if !row.Rule.Permit || row.SetBy != f.panel || row.Rule.Selection.Permission.ResourceProfile != LegacyExactResourceProfile || string(row.Rule.Selection.Selector.Target) != `"app:editor"` {
			t.Fatal(row)
		}
	}
	check := f.p.CheckLegacyPermissionEffectContext(t.Context(), effect, edit.Revision)
	if check.Outcome != wire.BatchCheckOutcomeChecked || len(check.Outcomes) != 3 || slices.ContainsFunc(check.Outcomes, func(o wire.DecisionOutcome) bool { return o != wire.DecisionOutcomePermitted }) {
		t.Fatal(check)
	}
	replay, err := f.p.ApplyLegacyPermissionEffect(t.Context(), edit.Revision, effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || replay.Outcome != wire.PolicyEditOutcomeConflict || len(replay.Current) != 3 {
		t.Fatal(replay, err)
	}
	undone, err := f.p.UndoLegacyPermissionEffect(t.Context(), edit.Revision, effect, nil, operatorQ1, func() error { return nil })
	if err != nil || undone.Outcome != wire.PolicyEditOutcomeApplied || len(undone.Current) != 0 {
		t.Fatal(undone, err)
	}
	for _, selection := range effect.Selections {
		if got := f.p.Decide(f.appA, selection.Permission.Action, "app:editor"); got.Outcome != wire.DecisionOutcomeNotGranted {
			t.Fatal(got)
		}
	}
}

func TestLegacyCompleteEffectDenyIsAtomicAndOldBatchStaysTwo(t *testing.T) {
	f, effect := legacyCompleteFixture(t)
	deny := false
	if _, err := f.p.ChangeRule(f.revision(t), effect.Subject, effect.Selections[2].Permission.Action, "app:editor", RuleEdit{Permit: &deny, By: f.panel, Exact: true}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := f.revision(t)
	edit, err := f.p.ApplyLegacyPermissionEffect(t.Context(), before, effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict || len(edit.Current) != 1 || edit.Current[0].Rule.Permit || f.revision(t) != before {
		t.Fatal(edit, err)
	}
	for _, selection := range effect.Selections[:2] {
		if got := f.p.Decide(f.appA, selection.Permission.Action, "app:editor"); got.Outcome != wire.DecisionOutcomeNotGranted {
			t.Fatal("partial grant", got)
		}
	}
	rules, _ := f.p.legacyPermissionRules(effect)
	old, err := f.p.ChangeRules(before, rules, RuleEdit{By: f.panel, Exact: true}, func() error { return nil })
	if err != nil || old.Outcome != wire.PolicyEditOutcomeInvalid {
		t.Fatal("old batch bound changed", old, err)
	}
}

func TestLegacyCompleteEffectEnrollmentExpiryStopAndReplacement(t *testing.T) {
	f, effect := legacyCompleteFixture(t)
	f.enroll(t, time.Hour)
	edit, err := f.p.ChangeLegacyPermissionEffectUnderAnswer(t.Context(), f.holder, effect, "routine application answer", operatorQ1, true, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || len(edit.Current) != 3 {
		t.Fatal(edit, err)
	}
	for _, row := range edit.Current {
		if row.SetBy != f.holder || row.Expires == "" {
			t.Fatal("missing enrollment attribution/expiry", row)
		}
	}
	permit := true
	_, err = f.p.ChangeRule(f.revision(t), effect.Subject, effect.Selections[0].Permission.Action, "app:editor", RuleEdit{Permit: &permit, By: f.panel, Exact: true}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	undo, err := f.p.UndoLegacyPermissionEffect(t.Context(), f.revision(t), effect, &f.holder, operatorQ1, func() error { return nil })
	if err != nil || undo.Outcome != wire.PolicyEditOutcomeApplied || len(undo.Current) != 1 || undo.Current[0].SetBy != f.panel {
		t.Fatal("replacement was not preserved", undo, err)
	}
	f.stop(t)
	stopped, err := f.p.ChangeLegacyPermissionEffectUnderAnswer(t.Context(), f.holder, effect, "late answer", operatorQ2, true, func() error { return nil })
	if !errors.Is(err, ErrNoMetaRule) || stopped.Outcome != wire.PolicyEditOutcomeUnavailable {
		t.Fatal("stopped holder wrote effect", stopped, err)
	}
}

func TestLegacyCompleteEffectCancelledAndUnavailableCommitRecovery(t *testing.T) {
	f, effect := legacyCompleteFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := f.revision(t)
	edit, err := f.p.ApplyLegacyPermissionEffect(ctx, before, effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if !errors.Is(err, context.Canceled) || edit.Outcome != wire.PolicyEditOutcomeUnavailable || f.revision(t) != before {
		t.Fatal(edit, err)
	}
	unavailable := errors.New("checked settlement unavailable")
	remove := f.p.OnChangeChecked(func() error { return unavailable })
	edit, err = f.p.ApplyLegacyPermissionEffect(t.Context(), before, effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if !errors.Is(err, unavailable) || edit.Outcome != wire.PolicyEditOutcomeUnavailable || len(edit.Current) != 0 {
		t.Fatal(edit, err)
	}
	remove()
	if applied, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || !applied {
		t.Fatal("lost durable commit receipt", applied, err)
	}
	for _, s := range effect.Selections {
		if d := f.p.Decide(effect.Subject, s.Permission.Action, "app:editor"); d.Outcome != wire.DecisionOutcomePermitted {
			t.Fatal(d)
		}
	}
	revision := f.revision(t)
	edit, err = f.p.ApplyLegacyPermissionEffect(t.Context(), revision, effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict || len(edit.Current) != 3 || f.revision(t) != revision {
		t.Fatal("reconcile replay", edit, err)
	}
}

func TestLegacyCompleteEffectExpiredEnrollmentWritesNothing(t *testing.T) {
	f, effect := legacyCompleteFixture(t)
	f.enroll(t, time.Hour)
	f.mu.Lock()
	f.now = f.now.Add(2 * time.Hour)
	f.mu.Unlock()
	edit, err := f.p.ChangeLegacyPermissionEffectUnderAnswer(t.Context(), f.holder, effect, "expired answer", operatorQ1, true, func() error { return nil })
	if !errors.Is(err, ErrNoMetaRule) || edit.Outcome != wire.PolicyEditOutcomeUnavailable {
		t.Fatal(edit, err)
	}
	for _, s := range effect.Selections {
		if d := f.p.Decide(effect.Subject, s.Permission.Action, "app:editor"); d.Outcome != wire.DecisionOutcomeNotGranted {
			t.Fatal(d)
		}
	}
}

func TestOperatorAllowCheckedSettlementUnavailableRetainsRecoveryProof(t *testing.T) {
	f := newMetaFixture(t)
	permit := true
	rules := []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "output:image", Permit: true}}
	unavailable := errors.New("standing decision unavailable")
	remove := f.p.OnChangeChecked(func() error { return unavailable })
	edit, err := f.p.ApplyFirstUseAllow(t.Context(), f.revision(t), rules, RuleEdit{Permit: &permit, By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if !errors.Is(err, unavailable) || edit.Outcome != wire.PolicyEditOutcomeUnavailable {
		t.Fatalf("reply: %+v %v", edit, err)
	}
	if yes, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || !yes {
		t.Fatalf("committed answer proof: %v %v", yes, err)
	}
	if got := f.p.Decide(f.appA, decisionAction, "output:image"); got.Outcome != wire.DecisionOutcomePermitted {
		t.Fatalf("committed permit lost: %+v", got)
	}
	remove()
	current := f.revision(t)
	edit, err = f.p.ApplyFirstUseAllow(t.Context(), current, rules, RuleEdit{Permit: &permit, By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict || f.revision(t) != current {
		t.Fatalf("reconcile/replay: %+v %v", edit, err)
	}
}

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
