package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestPermitAdmissionAllLegacyWritersAndRevocation(t *testing.T) {
	for _, writer := range []string{"set", "operator", "grouped", "responder"} {
		t.Run(writer, func(t *testing.T) {
			f := newMetaFixture(t)
			f.enroll(t, MetaRuleLapse)
			prepared, guarded := 0, 0
			refused := errors.New("receiver changed")
			if err := f.p.ConfigurePermitAdmission(decisionAction, func(_ context.Context, s wire.Subject, selection wire.PermissionSelection) (func() error, error) {
				prepared++
				if s != normalizedFixtureSubject(t, f.appA) || selection.Permission.Action != decisionAction {
					t.Fatal(s, selection)
				}
				return func() error { guarded++; return refused }, nil
			}); err != nil {
				t.Fatal(err)
			}
			permit := true
			var err error
			switch writer {
			case "set":
				err = f.p.Set(f.appA, decisionAction, "target", true)
			case "operator":
				_, err = f.p.ChangeRule(f.revision(t), f.appA, decisionAction, "target", RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil })
			case "grouped":
				_, err = f.p.ChangeRules(f.revision(t), []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "target", Permit: true}}, RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil })
			case "responder":
				_, err = f.p.ChangeRuleUnderAnswer(f.holder, f.appA, decisionAction, "target", true, "answer", "", func() error { return nil })
			}
			if !errors.Is(err, refused) || prepared != 1 || guarded != 1 {
				t.Fatal(err, prepared, guarded)
			}
			if got := f.p.Decide(f.appA, decisionAction, "target"); got.Outcome == wire.DecisionOutcomePermitted {
				t.Fatal(got)
			}
			if err := f.p.Set(f.appA, decisionAction, "target", false); err != nil {
				t.Fatal(err)
			}
			if err := f.p.Revoke(f.appA, decisionAction, "target"); err != nil {
				t.Fatal(err)
			}
			if prepared != 1 || guarded != 1 {
				t.Fatal("non-permit entered provider", prepared, guarded)
			}
		})
	}
}

func TestPermitAdmissionInvalidatesTypedLegacyProfile(t *testing.T) {
	base, err := NewDefinitionCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := func(raw []byte) bool {
		var value string
		return json.Unmarshal(raw, &value) == nil && boundedDecisionString(value, 1024)
	}
	definition := wire.PermissionDefinition{Action: selectorUse, OwnerContract: "example.service/user@2", Operations: []string{"example.service/user@2#Use"}, ResourceProfile: LegacyExactResourceProfile, ResourceType: "string", EnforcedBy: []string{"example.service/user@2"}, Disclosure: "Use target", Lifecycle: "Target registration", FirstUse: wire.PermissionFirstUseNone, Served: true}
	catalog, err := base.WithSelectors([]wire.SelectorPermissionDefinition{{Definition: definition, Label: "Use", Collection: "example.targets", RequestType: "string", SupportedSelectors: []wire.ResourceSelectorKind{wire.ResourceSelectorKindOne}}}, map[string]ResourceProfile{LegacyExactResourceProfile: {Prepare: func(raw []byte) ([]byte, error) {
		if !valid(raw) {
			return nil, errors.New("invalid")
		}
		return bytes.Clone(raw), nil
	}, Validate: valid, Equal: bytes.Equal}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadDecisionPolicyWithDefinitions(filepath.Join(t.TempDir(), "policy.json"), []string{selectorUse}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	f := newMetaFixture(t)
	selection := func(target string) wire.PermissionSelection {
		raw, _ := json.Marshal(target)
		return wire.PermissionSelection{Permission: wire.PermissionKey{Action: selectorUse, ResourceProfile: LegacyExactResourceProfile}, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: raw}}
	}
	for _, row := range []struct {
		s      wire.Subject
		target string
		permit bool
	}{{f.appA, "target", true}, {f.appB, "target", false}, {f.appA, "other", true}} {
		out, err := p.SetSelectorRuleContext(t.Context(), selectorRevision(t, p), wire.SelectorRule{Subject: row.s, Selection: selection(row.target), Permit: row.permit}, RuleEdit{By: f.panel}, func() error { return nil })
		if err != nil || out.Outcome != wire.PolicyEditOutcomeApplied {
			t.Fatal(out, err)
		}
	}
	if err := p.ConfigurePermitAdmission(selectorUse, func(context.Context, wire.Subject, wire.PermissionSelection) (func() error, error) {
		return func() error { return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.InvalidateProviderPermitsContext(t.Context(), "target"); err != nil {
		t.Fatal(err)
	}
	_, rows, err := p.SelectorSnapshotContext(t.Context())
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	for _, row := range rows {
		if row.Rule.Permit && bytes.Equal(row.Rule.Selection.Selector.Target, selection("target").Selector.Target) {
			t.Fatal("typed permit retained", row)
		}
	}
}

func TestPermitAdmissionRechecksPreparedTargetAndExactInvalidation(t *testing.T) {
	f := newMetaFixture(t)
	var current atomic.Int64
	current.Store(1)
	prepared, release := make(chan struct{}), make(chan struct{})
	if err := f.p.ConfigurePermitAdmission(decisionAction, func(context.Context, wire.Subject, wire.PermissionSelection) (func() error, error) {
		captured := current.Load()
		close(prepared)
		<-release
		return func() error {
			if captured != current.Load() {
				return errors.New("receiver changed")
			}
			return nil
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.p.Set(f.appA, decisionAction, "target", true) }()
	<-prepared
	current.Store(2)
	close(release)
	if err := <-done; err == nil {
		t.Fatal("stale prepared permit committed")
	}
	// Seed retained permits through the unchanged default provider, then reopen
	// with admission configured, as an ordinary lifecycle owner does.
	path := filepath.Join(t.TempDir(), "retained.json")
	p, err := LoadDecisionPolicy(path, []string{decisionAction, "example/other"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		s      wire.Subject
		a, r   string
		permit bool
	}{{f.appA, decisionAction, "target", true}, {f.appB, decisionAction, "target", false}, {f.appA, decisionAction, "other", true}, {f.appA, "example/other", "target", true}} {
		if err := p.Set(row.s, row.a, row.r, row.permit); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.ConfigurePermitAdmission(decisionAction, func(context.Context, wire.Subject, wire.PermissionSelection) (func() error, error) {
		return func() error { return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.InvalidateProviderPermitsContext(t.Context(), "target"); err != nil {
		t.Fatal(err)
	}
	if p.Decide(f.appA, decisionAction, "target").Outcome == wire.DecisionOutcomePermitted || p.Decide(f.appB, decisionAction, "target").Outcome != wire.DecisionOutcomeDenied || p.Decide(f.appA, decisionAction, "other").Outcome != wire.DecisionOutcomePermitted || p.Decide(f.appA, "example/other", "target").Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("invalidation changed unrelated rules")
	}
	if err := p.InvalidateProviderPermitsContext(t.Context(), "target"); err != nil {
		t.Fatal("idempotent replay", err)
	}
}

func TestPermitAdmissionTypedAndPreparationFailure(t *testing.T) {
	p, err := LoadDecisionPolicyWithDefinitions(filepath.Join(t.TempDir(), "policy.json"), []string{selectorUse}, testSelectorCatalog(t, true))
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t)
	refused := errors.New("target unavailable")
	calls := 0
	if err := p.ConfigurePermitAdmission(selectorUse, func(context.Context, wire.Subject, wire.PermissionSelection) (func() error, error) {
		calls++
		return nil, refused
	}); err != nil {
		t.Fatal(err)
	}
	_, err = p.SetSelectorRuleContext(t.Context(), selectorRevision(t, p), wire.SelectorRule{Subject: s, Selection: testSelection(selectorUse, "alpha"), Permit: true}, RuleEdit{By: s}, func() error { return nil })
	if !errors.Is(err, refused) || calls != 1 {
		t.Fatal(err, calls)
	}
	if err := p.ConfigurePermitAdmission(selectorUse, func(context.Context, wire.Subject, wire.PermissionSelection) (func() error, error) { return nil, nil }); err == nil {
		t.Fatal("configuration replaced")
	}
}
