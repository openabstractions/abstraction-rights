package rights

import (
	"encoding/json"
	"os"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

const pairedWrite = "abstraction.storage/content.write"

func answerGrant(t *testing.T, f *metaFixture, target wire.Subject, action, id string) {
	t.Helper()
	edit, err := f.p.ChangeRuleUnderAnswer(f.holder, target, action, "output:image", true, "answered for the person", id, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("grant %s/%s: %+v %v", action, id, edit, err)
	}
}

func TestUndoRemovesOnlyThisAnswersStillCurrentPairedEffects(t *testing.T) {
	f := newMetaFixture(t)
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	f.enroll(t, MetaRuleLapse)
	answerGrant(t, f, f.appA, pairedWrite, "Q1")
	answerGrant(t, f, f.appA, decisionAction, "Q1")
	// Q1's write ends; Q2 creates a new write at the fixed service time,
	// while its paired read is an O5 no-op still owned by Q1.
	if err := f.p.Revoke(f.appA, pairedWrite, "output:image"); err != nil {
		t.Fatal(err)
	}
	answerGrant(t, f, f.appA, pairedWrite, "Q2")
	answerGrant(t, f, f.appA, decisionAction, "Q2")
	revision := f.revision(t)
	edit, err := f.p.RevokeAnswerPermits(revision, f.holder, f.appA, []string{pairedWrite, decisionAction}, "output:image", "Q2", func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("Q2 undo %+v %v", edit, err)
	}
	if f.p.Decide(f.appA, pairedWrite, "output:image").Outcome != wire.DecisionOutcomeNotGranted || f.decide(f.appA) != wire.DecisionOutcomePermitted {
		t.Fatal("Q2 Undo did not preserve the older paired read")
	}
	edit, err = f.p.RevokeAnswerPermits(edit.Revision, f.holder, f.appA, []string{pairedWrite, decisionAction}, "output:image", "Q2", func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatalf("zero-match Undo %+v %v", edit, err)
	}
	edit, err = f.p.RevokeAnswerPermits(f.revision(t), f.holder, f.appA, []string{pairedWrite, decisionAction}, "output:image", "Q1", func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || f.decide(f.appA) != wire.DecisionOutcomeNotGranted {
		t.Fatalf("Q1 read Undo %+v %v", edit, err)
	}
}

func TestUndoPreservesReplacementAndFixedClockABA(t *testing.T) {
	f := newMetaFixture(t)
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	f.enroll(t, MetaRuleLapse)
	answerGrant(t, f, f.appA, pairedWrite, "Q1")
	answerGrant(t, f, f.appA, decisionAction, "Q1")
	oldRevision := f.revision(t)
	for _, action := range []string{pairedWrite, decisionAction} {
		if err := f.p.Revoke(f.appA, action, "output:image"); err != nil {
			t.Fatal(err)
		}
		answerGrant(t, f, f.appA, action, "Q2")
	}
	if f.revision(t) == oldRevision {
		t.Fatal("same-millisecond replacement recreated the old policy revision")
	}
	// Q2's read is replaced by Q3 while its write remains; Undo Q2 removes
	// that write but never the later read.
	if err := f.p.Revoke(f.appA, decisionAction, "output:image"); err != nil {
		t.Fatal(err)
	}
	answerGrant(t, f, f.appA, decisionAction, "Q3")
	edit, err := f.p.RevokeAnswerPermits(f.revision(t), f.holder, f.appA, []string{pairedWrite, decisionAction}, "output:image", "Q2", func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || f.decide(f.appA) != wire.DecisionOutcomePermitted {
		t.Fatalf("replacement lost %+v %v", edit, err)
	}
	if f.p.Decide(f.appA, pairedWrite, "output:image").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("Q2's remaining write was not removed")
	}
	// The persisted private identity survives a fresh policy instance.
	reopened, err := LoadDecisionPolicy(f.p.path, []string{MetaAnswerAction, decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	reopened.Clock = f.p.Clock
	if edit, err := reopened.RevokeAnswerPermits(f.revision(t), f.holder, f.appA, []string{decisionAction}, "output:image", "Q3", func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("restart Q3 Undo %+v %v", edit, err)
	}
}

func TestStopDefaultKeepsStampedGrantAndOptionalCleanupPreservesBlocks(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	answerGrant(t, f, f.appA, decisionAction, "Q1")
	permit, deny := true, false
	if _, err := f.p.ChangeRule(f.revision(t), f.appC, decisionAction, "output:image", RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ChangeRule(f.revision(t), f.appC, decisionAction, "input:image", RuleEdit{Permit: &deny, By: f.holder}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ChangeRule(f.revision(t), f.appB, MetaAnswerAction, MetaScopeApps, RuleEdit{Permit: &permit, By: f.panel, TTL: MetaRuleLapse}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if edit, err := f.p.ChangeRuleUnderAnswer(f.appB, f.appC, decisionAction, "other", true, "", "Q-other", func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("other assistant %+v %v", edit, err)
	}
	before := f.p.ReadRule(f.appA, decisionAction, "output:image").Record.Expires
	if edit, err := f.p.StopAnswerer(f.revision(t), f.holder, false, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("stop %+v %v", edit, err)
	}
	if read := f.p.ReadRule(f.appA, decisionAction, "output:image"); read.Record == nil || read.Record.Expires != before {
		t.Fatalf("stop changed stamped expiry %+v", read)
	}
	if edit, err := f.p.ChangeRuleUnderAnswer(f.holder, f.appB, decisionAction, "output:image", true, "", "Q2", func() error { return nil }); err != ErrNoMetaRule || edit.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatalf("answer after Stop %+v %v", edit, err)
	}
	if edit, err := f.p.StopAnswerer(f.revision(t), f.holder, true, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("cleanup %+v %v", edit, err)
	}
	if f.decide(f.appA) != wire.DecisionOutcomeNotGranted {
		t.Fatal("cleanup left assistant permit")
	}
	if f.decide(f.appC) != wire.DecisionOutcomePermitted || f.p.Decide(f.appC, decisionAction, "input:image").Outcome != wire.DecisionOutcomeDenied || f.p.Decide(f.appC, decisionAction, "other").Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("cleanup removed a human permit, deny or another answerer's permit")
	}
}

func TestLegacyGrantWithoutQuestionIDCannotBeTargetedByUndo(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	if _, err := f.answer(f.appA); err != nil {
		t.Fatal(err)
	}
	// A real @2 file has no private question identity. Reading it must retain
	// the grant, and a later write upgrades the profile without inventing one.
	data, err := os.ReadFile(f.p.path)
	if err != nil {
		t.Fatal(err)
	}
	var old decisionFile
	if err := json.Unmarshal(data, &old); err != nil {
		t.Fatal(err)
	}
	old.Profile = previousDecisionProfile
	data, err = json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.p.path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadDecisionPolicy(f.p.path, []string{MetaAnswerAction, decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	reopened.Clock = f.p.Clock
	f.p = reopened
	data, err = os.ReadFile(f.p.path)
	if err != nil || !containsProfile(data, previousDecisionProfile) {
		t.Fatalf("reading old profile changed it: %s %v", data, err)
	}
	edit, err := f.p.RevokeAnswerPermits(f.revision(t), f.holder, f.appA, []string{decisionAction}, "output:image", "Q-old", func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict || f.decide(f.appA) != wire.DecisionOutcomePermitted {
		t.Fatalf("legacy grant was guessed %+v %v", edit, err)
	}
	if edit, err := f.p.StopAnswerer(f.revision(t), f.holder, true, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || f.decide(f.appA) != wire.DecisionOutcomeNotGranted {
		t.Fatalf("legacy app-wide cleanup %+v %v", edit, err)
	}
	data, err = os.ReadFile(f.p.path)
	if err != nil || !containsProfile(data, DecisionProfile) {
		t.Fatalf("old profile was not migrated on edit: %s %v", data, err)
	}
}

func TestVersionTwoDecisionFileReadsThenMigratesOnWrite(t *testing.T) {
	f := newMetaFixture(t)
	old := decisionFile{Profile: previousDecisionProfile}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.p.path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadDecisionPolicy(f.p.path, []string{MetaAnswerAction, decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Set(f.appA, decisionAction, "output:image", true); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(f.p.path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || !containsProfile(data, DecisionProfile) {
		t.Fatalf("version 2 was not migrated: %s", data)
	}
}

func containsProfile(data []byte, profile string) bool {
	var f struct {
		Profile string `json:"profile"`
	}
	return json.Unmarshal(data, &f) == nil && f.Profile == profile
}
