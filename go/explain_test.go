package rights

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestQuietMetaDecisionRechecksCurrentHolder(t *testing.T) {
	f := newMetaFixture(t)
	ctx := context.Background()
	for _, enrolled := range []bool{false, true} {
		if enrolled {
			f.enroll(t, MetaRuleLapse)
		}
		for _, unavailable := range []bool{false, true} {
			f.p.MetaHolder = func(wire.Subject) error {
				if unavailable {
					return ErrMetaHolderUnavailable
				}
				return ErrMetaHolder
			}
			want := wire.DecisionOutcomeForbidden
			if unavailable {
				want = wire.DecisionOutcomeUnavailable
			}
			got := f.p.ExplainForContext(ctx, f.holder, MetaAnswerAction, MetaScopeApps)
			if got.Outcome != want || got.PolicyRevision != "" || got.Source != nil || got.DefaultName != "" {
				t.Errorf("enrolled=%t unavailable=%t: %+v", enrolled, unavailable, got)
			}
			if got := f.p.DecideContext(ctx, f.holder, MetaAnswerAction, MetaScopeApps); got.Outcome != want || got.PolicyRevision != "" {
				t.Errorf("decision: %+v", got)
			}
		}
		f.p.MetaHolder = nil
	}
	// Plain legacy callback errors keep their old quiet-read behavior.
	f.p.MetaHolder = func(wire.Subject) error { return errors.New("legacy refusal") }
	wantExplained(t, explain(t, f.p, f.holder, MetaAnswerAction, MetaScopeApps), wire.DecisionOutcomePermitted, wire.DecisionSourceOwnRule, "")
	// Explicit denies and unrelated actions retain the deciding source.
	f.p.MetaHolder = func(wire.Subject) error { return ErrMetaHolderUnavailable }
	if err := f.p.Set(f.holder, MetaAnswerAction, MetaScopeApps, false); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, f.p, f.holder, MetaAnswerAction, MetaScopeApps), wire.DecisionOutcomeDenied, wire.DecisionSourceOwnRule, "")
	wantExplained(t, explain(t, f.p, f.holder, decisionAction, "other"), wire.DecisionOutcomeNotGranted, wire.DecisionSourceNone, "")
}

func TestMetaPermitUnavailableAndRechecksInsideMutation(t *testing.T) {
	f := newMetaFixture(t)
	permit := true
	edit := RuleEdit{Permit: &permit, By: f.panel, TTL: MetaRuleLapse}
	f.p.MetaHolder = func(wire.Subject) error { return ErrMetaHolderUnavailable }
	got, err := f.p.ChangeRule(f.revision(t), f.holder, MetaAnswerAction, MetaScopeApps, edit, func() error { return nil })
	if got.Outcome != wire.PolicyEditOutcomeUnavailable || !errors.Is(err, ErrMetaHolderUnavailable) {
		t.Fatal(got, err)
	}
	f.p.MetaHolder = nil
	got, err = f.p.ChangeRule(f.revision(t), f.holder, MetaAnswerAction, MetaScopeApps, edit, func() error {
		f.p.MetaHolder = func(wire.Subject) error { return ErrMetaHolderUnavailable }
		return nil
	})
	if got.Outcome != wire.PolicyEditOutcomeUnavailable || !errors.Is(err, ErrMetaHolderUnavailable) {
		t.Fatal(got, err)
	}
	if got := f.p.ReadRule(f.holder, MetaAnswerAction, MetaScopeApps); got.Outcome == wire.RuleReadOutcomeFound {
		t.Fatal("unavailable holder permit committed")
	}
}

func TestMetaHolderPreparationOperationScopeCancellationAndReentry(t *testing.T) {
	f := newMetaFixture(t)
	parent := context.Background()
	refreshes := 0
	f.p.RefreshMetaHolder = func(ctx context.Context) error {
		refreshes++
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	ctx, err := f.p.PrepareMetaHolderContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	permit := true
	got, err := f.p.ChangeRuleContext(ctx, f.revision(t), f.holder, MetaAnswerAction, MetaScopeApps, RuleEdit{Permit: &permit, By: f.panel, TTL: MetaRuleLapse}, func() error {
		// This is the real policy CAS callback. Its nested quiet evaluation
		// must use the prepared facts, acquiring no outer source locks.
		if _, err := f.p.prepareMetaOperation(ctx, MetaAnswerAction, MetaScopeApps); err != nil {
			return err
		}
		if refreshes != 1 {
			return errors.New("nested refresh")
		}
		return nil
	})
	if err != nil || got.Outcome != wire.PolicyEditOutcomeApplied || refreshes != 1 {
		t.Fatal(got, err, refreshes)
	}
	// Independent operations sharing the original parent always refresh.
	f.p.ExplainForContext(parent, f.holder, MetaAnswerAction, MetaScopeApps)
	f.p.ExplainForContext(parent, f.holder, MetaAnswerAction, MetaScopeApps)
	if refreshes != 3 {
		t.Fatal("stale operation context reused", refreshes)
	}
	other := newMetaFixture(t)
	otherRefreshes := 0
	other.p.RefreshMetaHolder = func(context.Context) error { otherRefreshes++; return nil }
	other.p.ExplainForContext(ctx, other.holder, MetaAnswerAction, MetaScopeApps)
	if otherRefreshes != 1 {
		t.Fatal("another policy reused foreign preparation", otherRefreshes)
	}
	cancelled, cancel := context.WithCancel(parent)
	cancel()
	if _, err := f.p.PrepareMetaHolderContext(cancelled); !errors.Is(err, ErrMetaHolderUnavailable) {
		t.Fatal(err)
	}
	if refreshes != 3 {
		t.Fatal("cancelled admission refreshed", refreshes)
	}
	f.p.RefreshMetaHolder = func(ctx context.Context) error {
		got := f.p.ExplainForContext(ctx, f.holder, MetaAnswerAction, MetaScopeApps)
		if got.Outcome != wire.DecisionOutcomeUnavailable || got.PolicyRevision != "" {
			t.Error("re-entry evaluated stale facts", got)
		}
		_, err := f.p.PrepareMetaHolderContext(ctx)
		return err
	}
	if _, err := f.p.PrepareMetaHolderContext(parent); !errors.Is(err, ErrMetaHolderUnavailable) {
		t.Fatal("re-entry", err)
	}
}

func TestQuietRefreshFailurePreservesEstablishedRefusals(t *testing.T) {
	for _, scenario := range []string{"own-deny", "typed-deny", "unknown", "permit", "none"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMetaFixture(t)
			if scenario == "own-deny" {
				if err := f.p.Set(f.holder, MetaAnswerAction, MetaScopeApps, false); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "permit" {
				f.enroll(t, MetaRuleLapse)
			}
			if scenario == "unknown" {
				var err error
				f.p, err = LoadDecisionPolicy(filepath.Join(t.TempDir(), "unknown.json"), []string{decisionAction})
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "typed-deny" {
				catalog := testSelectorCatalog(t, true)
				var defs []wire.PermissionDefinition
				for _, definition := range catalog.Definitions() {
					if definition.ResourceProfile == LegacyExactResourceProfile {
						defs = append(defs, definition)
					}
				}
				defs = append(defs, wire.PermissionDefinition{Action: MetaAnswerAction, OwnerContract: "abstraction.asks/responder@1", Operations: []string{"abstraction.asks/responder@1#Answer"}, ResourceProfile: LegacyExactResourceProfile, ResourceType: "string", EnforcedBy: []string{"abstraction.asks/responder@1"}, Disclosure: "Answer", Lifecycle: "Routine questions", FirstUse: wire.PermissionFirstUseNone, Served: true})
				base, err := NewDefinitionCatalog(defs, catalog.profiles)
				if err != nil {
					t.Fatal(err)
				}
				links := append([]LegacyEquivalence{}, catalog.selectors.equivalents...)
				links = append(links, LegacyEquivalence{Action: MetaAnswerAction, Resource: MetaScopeApps, Permission: testSelection(selectorUse, "").Permission, Mode: "fixture-meta@1"})
				var typed []wire.SelectorPermissionDefinition
				for _, definition := range catalog.SelectorDefinitions() {
					if definition.Definition.ResourceProfile != LegacyExactResourceProfile {
						typed = append(typed, definition)
					}
				}
				base, err = base.WithSelectors(typed, catalog.selectors.profiles, catalog.PermissionBundles(), links)
				if err != nil {
					t.Fatal(err)
				}
				f.p, err = LoadDecisionPolicyWithDefinitions(filepath.Join(t.TempDir(), "typed.json"), []string{MetaAnswerAction, selectorUse, selectorCreate, selectorManage}, base)
				if err != nil {
					t.Fatal(err)
				}
				setTestSelector(t, f.p, f.holder, testSelection(selectorUse, ""), false)
			}
			if err := f.p.EnableRevisionDecisions("refresh-precedence-fixture"); err != nil {
				t.Fatal(err)
			}
			f.p.RefreshMetaHolder = func(context.Context) error { return errors.New("actual declaration reload failed") }
			want := wire.DecisionOutcomeUnavailable
			source := wire.DecisionSourceNone
			switch scenario {
			case "own-deny":
				want, source = wire.DecisionOutcomeDenied, wire.DecisionSourceOwnRule
			case "typed-deny":
				want, source = wire.DecisionOutcomeDenied, wire.DecisionSourceTypedBlock
			case "unknown":
				want = wire.DecisionOutcomeUnknownAction
			}
			got := f.p.ExplainForContext(t.Context(), f.holder, MetaAnswerAction, MetaScopeApps)
			if want == wire.DecisionOutcomeUnavailable {
				if got.Outcome != want || got.PolicyRevision != "" || got.Source != nil {
					t.Errorf("%s: %+v", scenario, got)
				}
			} else if got.Outcome != want || got.PolicyRevision == "" || got.Source == nil || *got.Source != source {
				t.Errorf("%s lost established refusal: %+v", scenario, got)
			}
			if got := f.p.DecideContext(t.Context(), f.holder, MetaAnswerAction, MetaScopeApps); got.Outcome != want {
				t.Errorf("decision: %+v", got)
			}
			if got := f.p.DecideForAtLeastRevisionContext(t.Context(), f.holder, MetaAnswerAction, MetaScopeApps, ""); got.Decision.Outcome != want {
				t.Errorf("revision decision: %+v", got)
			}
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			if got := f.p.ExplainForContext(cancelled, f.holder, MetaAnswerAction, MetaScopeApps); got.Outcome != wire.DecisionOutcomeUnavailable || got.PolicyRevision != "" || got.Source != nil {
				t.Error("cancelled disclosure", got)
			}
		})
	}
}

func explain(t *testing.T, p *DecisionPolicy, s wire.Subject, action, resource string) wire.DecisionExplanation {
	t.Helper()
	return p.ExplainForContext(context.Background(), s, action, resource)
}

func wantExplained(t *testing.T, got wire.DecisionExplanation, outcome wire.DecisionOutcome, source wire.DecisionSource, name string) {
	t.Helper()
	if got.Outcome != outcome || got.Source == nil || *got.Source != source || got.DefaultName != name || got.PolicyRevision == "" {
		s := "<nil>"
		if got.Source != nil {
			s = got.Source.String()
		}
		t.Fatalf("explained %s/%s/%q, want %s/%s/%q", got.Outcome, s, got.DefaultName, outcome, source, name)
	}
}

// RIGHTS-O14: the explanation is the decision's own evaluation with the step
// that decided it: a default by name, the program's own rule over it, a
// default the program is excluded from, and none. It records nothing.
func TestExplainForNamesTheDecidingStep(t *testing.T) {
	script := scriptHost(t)
	p := defaultsPolicy(t, filepath.Join(t.TempDir(), "decisions.json"), script)
	s := subject(t)
	before := selectorRevision(t, p)
	got := explain(t, p, s, ActionJobSubmit, ResourceDownloadJobs)
	wantExplained(t, got, wire.DecisionOutcomePermitted, wire.DecisionSourceAccountDefault, DefaultDownload)
	if d := p.Decide(s, ActionJobSubmit, ResourceDownloadJobs); d.Outcome != got.Outcome || d.PolicyRevision != got.PolicyRevision {
		t.Fatalf("the explanation %+v differs from the decision %+v", got, d)
	}
	wantExplained(t, explain(t, p, s, ActionApplicationAnnounce, "app:alpha"), wire.DecisionOutcomePermitted, wire.DecisionSourceAccountDefault, DefaultAnnounce)
	wantExplained(t, explain(t, p, script, ActionJobSubmit, ResourceDownloadJobs), wire.DecisionOutcomeNotGranted, wire.DecisionSourceDefaultExcluded, DefaultDownload)
	wantExplained(t, explain(t, p, s, ActionJobSubmit, "other-jobs"), wire.DecisionOutcomeNotGranted, wire.DecisionSourceNone, "")
	if after := selectorRevision(t, p); after != before {
		t.Fatalf("explaining changed the revision %s -> %s", before, after)
	}
	if err := p.Set(s, ActionJobSubmit, ResourceDownloadJobs, false); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, s, ActionJobSubmit, ResourceDownloadJobs), wire.DecisionOutcomeDenied, wire.DecisionSourceOwnRule, "")
	if err := p.Set(s, ActionJobSubmit, ResourceDownloadJobs, true); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, s, ActionJobSubmit, ResourceDownloadJobs), wire.DecisionOutcomePermitted, wire.DecisionSourceOwnRule, "")
	if got := explain(t, p, wire.Subject{Account: s.Account, Program: "relative.exe"}, ActionJobSubmit, ResourceDownloadJobs); got.Outcome != wire.DecisionOutcomeInvalid || got.Source != nil || got.PolicyRevision != "" {
		t.Fatalf("an invalid subject explained %+v", got)
	}
}

// RIGHTS-O14: a live typed Block decides before the program's own exact
// permit, and the explanation says so.
func TestExplainForNamesATypedBlock(t *testing.T) {
	p, s := testSelectorPolicy(t)
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
	if err := p.Set(s, selectorUse, "name:alpha", true); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, s, selectorUse, "name:alpha"), wire.DecisionOutcomeDenied, wire.DecisionSourceTypedBlock, "")
	wantExplained(t, explain(t, p, s, selectorUse, "name:beta"), wire.DecisionOutcomeNotGranted, wire.DecisionSourceNone, "")
}
