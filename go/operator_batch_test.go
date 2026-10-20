package rights

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestGroupedRulesAcceptSameFileAliases(t *testing.T) {
	f := newMetaFixture(t)
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(f.appA.Program), "alias.exe")
	if err := os.Link(f.appA.Program, alias); err != nil {
		t.Fatal(err)
	}
	permit := true
	rules := pairedBatch(f)
	rules[1].Subject.Program = alias
	edit, err := f.p.ChangeRules(f.revision(t), rules, RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("same-file grouped subjects: %+v %v", edit, err)
	}
	for _, rule := range rules {
		if f.p.Decide(rule.Subject, rule.Action, rule.Resource).Outcome != wire.DecisionOutcomePermitted {
			t.Fatalf("group member was not written: %+v", rule)
		}
		if read := f.p.ReadRule(rule.Subject, rule.Action, rule.Resource); read.Record == nil || read.Record.Rule.Subject.Program != rule.Subject.Program {
			t.Fatalf("group member spelling was not retained: %+v", read)
		}
	}
	for _, different := range []wire.Subject{f.appB, {Account: "another-account", Program: alias}} {
		rules[1].Subject = different
		before := f.revision(t)
		edit, err := f.p.ChangeRules(before, rules, RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil })
		if err != nil || edit.Outcome != wire.PolicyEditOutcomeInvalid || f.revision(t) != before {
			t.Fatalf("different subject changed grouped state: %+v %v", edit, err)
		}
	}
	for _, alter := range []func(*wire.PolicyRule){
		func(r *wire.PolicyRule) { r.Resource = "other" },
		func(r *wire.PolicyRule) { r.Action = pairedWrite },
		func(r *wire.PolicyRule) { r.Permit = false },
	} {
		bad := pairedBatch(f)
		alter(&bad[1])
		before := f.revision(t)
		edit, err := f.p.ChangeRules(before, bad, RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil })
		if err != nil || edit.Outcome != wire.PolicyEditOutcomeInvalid || f.revision(t) != before {
			t.Fatalf("invalid group changed state: %+v %v", edit, err)
		}
	}
}

func pairedBatch(f *metaFixture) []wire.PolicyRule {
	return []wire.PolicyRule{
		{Subject: f.appA, Action: pairedWrite, Resource: "output:image", Permit: true},
		{Subject: f.appA, Action: decisionAction, Resource: "output:image", Permit: true},
	}
}

func TestGroupedAnswerAndExactDelegationNeverLeakWriteOverReadDeny(t *testing.T) {
	f := newMetaFixture(t)
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	f.enroll(t, MetaRuleLapse)
	deny, permit := false, true
	if _, err := f.p.ChangeRule(f.revision(t), f.appA, decisionAction, "output:image", RuleEdit{Permit: &deny, By: f.panel}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if edit, err := f.p.ChangeRulesUnderAnswer(f.holder, f.appA, []string{pairedWrite, decisionAction}, "output:image", "answered", "Q1", func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatalf("enrolled pair %+v %v", edit, err)
	}
	if f.p.Decide(f.appA, pairedWrite, "output:image").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("enrolled write leaked over read deny")
	}
	deadline := f.now.Add(5 * time.Minute)
	if edit, err := f.p.ChangeRules(f.revision(t), pairedBatch(f), RuleEdit{Permit: &permit, By: f.holder, TTL: 5 * time.Minute, Exact: true, PreserveOtherSetter: true, Deadline: deadline}, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatalf("exact pair %+v %v", edit, err)
	}
	if f.p.Decide(f.appA, pairedWrite, "output:image").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("exact write leaked over read deny")
	}
	// A deliberate human operator allow may override its own earlier block;
	// it still commits the pair as one unit.
	if edit, err := f.p.ChangeRules(f.revision(t), pairedBatch(f), RuleEdit{Permit: &permit, By: f.panel, Exact: true}, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("human pair %+v %v", edit, err)
	}
	if f.decide(f.appA) != wire.DecisionOutcomePermitted || f.p.Decide(f.appA, pairedWrite, "output:image").Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("human pair did not land together")
	}
}

func TestGroupedExactDeadlineIsRecheckedAtEditTime(t *testing.T) {
	f := newMetaFixture(t)
	if err := f.p.RegisterAction(pairedWrite); err != nil {
		t.Fatal(err)
	}
	permit := true
	deadline := f.now.Add(time.Minute)
	edit, err := f.p.ChangeRules(f.revision(t), pairedBatch(f), RuleEdit{Permit: &permit, By: f.holder, TTL: 5 * time.Minute, Exact: true, PreserveOtherSetter: true, Deadline: deadline}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("bounded edit %+v %v", edit, err)
	}
	for _, rule := range pairedBatch(f) {
		read := f.p.ReadRule(rule.Subject, rule.Action, rule.Resource)
		if read.Record == nil {
			t.Fatalf("missing %s", rule.Action)
		}
		expiry, err := time.Parse(StampFormat, read.Record.Expires)
		if err != nil || !expiry.Before(deadline) {
			t.Fatalf("grant outlived delegation: %s %v", read.Record.Expires, err)
		}
	}
	// Simulate a delayed lock acquisition by advancing the service clock at
	// the in-edit authorization recheck. Neither target may be written.
	other := f.appB
	rules := pairedBatch(f)
	for i := range rules {
		rules[i].Subject = other
	}
	_, err = f.p.ChangeRules(f.revision(t), rules, RuleEdit{Permit: &permit, By: f.holder, TTL: 5 * time.Minute, Exact: true, PreserveOtherSetter: true, Deadline: deadline}, func() error { f.advance(2 * time.Minute); return nil })
	if !errors.Is(err, ErrRuleDeadline) || f.p.Decide(other, pairedWrite, "output:image").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("late grouped edit %v", err)
	}
}
