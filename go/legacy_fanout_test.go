package rights

import (
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// One answer may allow one action on several exact resources. Each rule is
// stored on its own, so removing one leaves the others.
func legacyFanoutFixture(t *testing.T) (*metaFixture, wire.PermissionEffect) {
	t.Helper()
	f := newMetaFixture(t)
	d := testDefinition()
	d.Action = "example/one"
	if err := f.p.RegisterAction(d.Action); err != nil {
		t.Fatal(err)
	}
	var err error
	f.p.Definitions, err = NewDefinitionCatalog([]wire.PermissionDefinition{d}, testProfiles())
	if err != nil {
		t.Fatal(err)
	}
	effect := wire.PermissionEffect{Subject: f.appA}
	for _, target := range []string{`"app:editor"`, `"app:viewer"`} {
		effect.Selections = append(effect.Selections, wire.PermissionSelection{Permission: wire.PermissionKey{Action: d.Action, ResourceProfile: LegacyExactResourceProfile}, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: []byte(target)}})
	}
	return f, effect
}

func TestLegacyFanoutAppliesEachRuleAndRemovesOneAlone(t *testing.T) {
	f, effect := legacyFanoutFixture(t)
	if compareEffectSelections(effect.Selections[0], effect.Selections[1]) >= 0 || compareEffectSelections(effect.Selections[0], effect.Selections[0]) != 0 {
		t.Fatal("one permission's One targets are not ordered by their bytes")
	}
	reversed := wire.PermissionEffect{Subject: effect.Subject, Selections: []wire.PermissionSelection{effect.Selections[1], effect.Selections[0]}}
	if _, ok := f.p.legacyPermissionRules(reversed); ok {
		t.Fatal("unsorted fanout projected")
	}
	duplicate := wire.PermissionEffect{Subject: effect.Subject, Selections: []wire.PermissionSelection{effect.Selections[0], effect.Selections[0]}}
	if _, ok := f.p.legacyPermissionRules(duplicate); ok {
		t.Fatal("repeated target projected")
	}
	edit, err := f.p.ApplyLegacyPermissionEffect(t.Context(), f.revision(t), effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied || len(edit.Current) != 2 {
		t.Fatal(edit, err)
	}
	for _, resource := range []string{"app:editor", "app:viewer"} {
		if got := f.p.Decide(f.appA, "example/one", resource); got.Outcome != wire.DecisionOutcomePermitted {
			t.Fatal(resource, got)
		}
	}
	if _, err := f.p.ChangeRule(f.revision(t), f.appA, "example/one", "app:viewer", RuleEdit{By: f.panel}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := f.p.Decide(f.appA, "example/one", "app:viewer"); got.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("removed pair still allowed", got)
	}
	if got := f.p.Decide(f.appA, "example/one", "app:editor"); got.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("removing one pair removed the other", got)
	}
	// The completed answer never applies again, while Undo removes the rule
	// it still holds.
	replay, err := f.p.ApplyLegacyPermissionEffect(t.Context(), f.revision(t), effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || replay.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatal(replay, err)
	}
	undone, err := f.p.UndoLegacyPermissionEffect(t.Context(), f.revision(t), effect, nil, operatorQ1, func() error { return nil })
	if err != nil || undone.Outcome != wire.PolicyEditOutcomeApplied || len(undone.Current) != 0 {
		t.Fatal(undone, err)
	}
	if got := f.p.Decide(f.appA, "example/one", "app:editor"); got.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal(got)
	}
	// The plain grouped edit keeps its one-resource bound.
	rules, ok := f.p.legacyPermissionRules(effect)
	if !ok {
		t.Fatal("fanout not projected")
	}
	permit := true
	if old, err := f.p.ChangeRules(f.revision(t), rules, RuleEdit{Permit: &permit, By: f.panel, Exact: true}, func() error { return nil }); err != nil || old.Outcome != wire.PolicyEditOutcomeInvalid {
		t.Fatal("ordinary batch accepted two resources", old, err)
	}
	if under, err := f.p.ChangeLegacyPermissionEffectUnderAnswer(t.Context(), f.holder, effect, "routine", operatorQ2, true, func() error { return nil }); err != nil || under.Outcome != wire.PolicyEditOutcomeInvalid {
		t.Fatal("responder path accepted fanout", under, err)
	}
}

func TestLegacyFanoutSkipsAllowedPairAndKeepsBlocks(t *testing.T) {
	f, effect := legacyFanoutFixture(t)
	permit, deny := true, false
	if _, err := f.p.ChangeRule(f.revision(t), f.appA, "example/one", "app:editor", RuleEdit{Permit: &permit, By: f.holder, Exact: true}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	edit, err := f.p.ApplyLegacyPermissionEffect(t.Context(), f.revision(t), effect, RuleEdit{By: f.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	for _, row := range edit.Current {
		target := string(row.Rule.Selection.Selector.Target)
		if target == `"app:editor"` && row.SetBy != f.holder || target == `"app:viewer"` && row.SetBy != f.panel {
			t.Fatal("an already allowed pair was rewritten", row)
		}
	}
	g, other := legacyFanoutFixture(t)
	if _, err := g.p.ChangeRule(g.revision(t), g.appA, "example/one", "app:viewer", RuleEdit{Permit: &deny, By: g.panel, Exact: true}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := g.revision(t)
	blocked, err := g.p.ApplyLegacyPermissionEffect(t.Context(), before, other, RuleEdit{By: g.panel, Exact: true}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || blocked.Outcome != wire.PolicyEditOutcomeConflict || g.revision(t) != before {
		t.Fatal("a block was overwritten or a partial grant written", blocked, err)
	}
}
