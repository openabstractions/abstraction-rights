package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestSelectorsLegacyCompletionPreservesCombinedReceiptCapacity(t *testing.T) {
	p, s := testSelectorPolicy(t)
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), true)
	f, _, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	f.AppliedOperatorAnswers = []string{fmt.Sprintf("%032x", 0)}
	for i := 1; i < MaxAppliedOperatorAnswers; i++ {
		f.AppliedTypedAnswers = append(f.AppliedTypedAnswers, fmt.Sprintf("%032x", i))
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	revision := selectorRevision(t, p)
	permit := true
	id := strings.Repeat("f", 32)
	result, err := p.ApplyFirstUseAllow(context.Background(), revision, []wire.PolicyRule{{Subject: s, Action: selectorUse, Resource: "name:beta", Permit: true}}, RuleEdit{By: s, Permit: &permit}, id, []string{f.AppliedOperatorAnswers[0], id}, func() error { return nil })
	if err == nil || result.Outcome != wire.PolicyEditOutcomeUnavailable {
		t.Fatal(result, err)
	}
	after, err := os.ReadFile(p.path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("overflow changed bytes", err)
	}
	if selectorRevision(t, p) != revision {
		t.Fatal("state became unreadable or changed")
	}
	if applied, err := p.AppliedFirstUseAllow(id); err != nil || applied {
		t.Fatal(applied, err)
	}
}

func TestSelectorsCompletionRechecksIntersectingLiveBlocks(t *testing.T) {
	for _, blockedAll := range []bool{true, false} {
		t.Run(fmt.Sprint(blockedAll), func(t *testing.T) {
			p, s := testSelectorPolicy(t)
			blocked, proposed := testSelection(selectorUse, "alpha"), testSelection(selectorUse, "")
			if blockedAll {
				blocked, proposed = proposed, blocked
			}
			setTestSelector(t, p, s, blocked, false)
			effect, err := p.Definitions.PreparePermissionEffect(s, []wire.PermissionSelection{proposed}, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(p.path)
			if err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat("a", 32)
			result, err := p.ApplyPermissionEffect(context.Background(), selectorRevision(t, p), effect, RuleEdit{By: s}, id, []string{id}, func() error { return nil })
			if err != nil || result.Outcome != wire.PolicyEditOutcomeConflict {
				t.Fatal(result, err)
			}
			after, err := os.ReadFile(p.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused completion changed bytes", err)
			}
			if applied, err := p.AppliedPermissionEffect(id); err != nil || applied {
				t.Fatal(applied, err)
			}
		})
	}
}

const selectorTestProfile = "example.resources/names@1"
const selectorUse = "example.service/use"
const selectorManage = "example.service/manage"
const selectorCreate = "example.service/create"

func testTarget(name string) []byte {
	return wire.EncodeRequest(&wire.Request{Op: "target", Name: name})
}
func testTargetValid(data []byte) bool {
	v, e := wire.DecodeRequest(data)
	return e == nil && v.Op == "target" && boundedDecisionString(v.Name, 64) && bytes.Equal(data, wire.EncodeRequest(v)) && bytes.Equal(data, testTarget(v.Name))
}
func testSelection(action, name string) wire.PermissionSelection {
	s := wire.PermissionSelection{Permission: wire.PermissionKey{Action: action, ResourceProfile: selectorTestProfile}, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindAll}}
	if name != "" {
		s.Selector.Kind = wire.ResourceSelectorKindOne
		s.Selector.Target = testTarget(name)
	}
	return s
}
func testSelectorCatalog(t *testing.T, served bool) *DefinitionCatalog {
	t.Helper()
	legacy := []wire.PermissionDefinition{{Action: selectorUse, OwnerContract: "example.service/user@1", Operations: []string{"example.service/user@1#Use"}, ResourceProfile: LegacyExactResourceProfile, ResourceType: "string", EnforcedBy: []string{"example.service/user@1"}, Disclosure: "Use", Lifecycle: "Name", FirstUse: wire.PermissionFirstUseNone, Served: true}}
	c, e := NewDefinitionCatalog(legacy, map[string]func(string) bool{LegacyExactResourceProfile: func(s string) bool { return boundedDecisionString(s, 1024) }})
	if e != nil {
		t.Fatal(e)
	}
	defs := []wire.SelectorPermissionDefinition{}
	for _, a := range []string{selectorCreate, selectorUse} {
		d := wire.SelectorPermissionDefinition{Definition: wire.PermissionDefinition{Action: a, OwnerContract: "example.service/user@2", Operations: []string{"example.service/user@2#Operate"}, ResourceProfile: selectorTestProfile, ResourceType: "example.Target", Disclosure: "Test named effect", Lifecycle: "Name reuse", FirstUse: wire.PermissionFirstUseNone, Served: served}, Label: a, Collection: "example.resources/names@1", AllEffect: "All current and future test names", RequestType: "example.Target"}
		if served {
			d.Definition.EnforcedBy = []string{"example.service/user@2"}
			d.SupportedSelectors = []wire.ResourceSelectorKind{wire.ResourceSelectorKindOne, wire.ResourceSelectorKindAll}
			d.FirstUseSelectors = []wire.ResourceSelectorKind{wire.ResourceSelectorKindOne, wire.ResourceSelectorKindAll}
		} else {
			d.AllEffect = ""
		}
		defs = append(defs, d)
	}
	profiles := map[string]ResourceProfile{selectorTestProfile: {Prepare: func(b []byte) ([]byte, error) {
		if !testTargetValid(b) {
			return nil, errors.New("invalid test target")
		}
		return slices.Clone(b), nil
	}, Validate: testTargetValid, Equal: bytes.Equal, AllowAll: true, Describe: func(b []byte) (string, error) {
		v, e := wire.DecodeRequest(b)
		if e != nil {
			return "", e
		}
		return v.Name, nil
	}}}
	members := []wire.PermissionKey{testSelection(selectorCreate, "").Permission, testSelection(selectorUse, "").Permission}
	bundle := wire.PermissionBundleDefinition{BundleRef: "example.resources/full-control@1", OwnerContract: "example.service/user@2", Label: "Full control v1", TargetType: "example.Target", SupportedSelectors: []wire.ResourceSelectorKind{wire.ResourceSelectorKindOne, wire.ResourceSelectorKindAll}, Members: members, Disclosure: "Create and Use; no future operations"}
	links := []LegacyEquivalence{{Action: selectorUse, Permission: testSelection(selectorUse, "").Permission, Mode: "named-use@1", Concrete: func(r string) ([]byte, bool) {
		name, ok := strings.CutPrefix(r, "name:")
		if !ok || !boundedDecisionString(name, 64) {
			return nil, false
		}
		return testTarget(name), true
	}}, {Action: selectorManage, Resource: "account", Permission: testSelection(selectorCreate, "").Permission, Mode: "saved-names@1"}}
	c, e = c.WithSelectors(defs, profiles, []wire.PermissionBundleDefinition{bundle}, links)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func testSelectorPolicy(t *testing.T) (*DecisionPolicy, wire.Subject) {
	t.Helper()
	p, e := LoadDecisionPolicyWithDefinitions(filepath.Join(t.TempDir(), "decisions.json"), []string{selectorUse, selectorCreate, selectorManage}, testSelectorCatalog(t, true))
	if e != nil {
		t.Fatal(e)
	}
	return p, subject(t)
}
func selectorRevision(t *testing.T, p *DecisionPolicy) string {
	t.Helper()
	s, e := p.OperatorSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	return s.Revision
}
func setTestSelector(t *testing.T, p *DecisionPolicy, s wire.Subject, selection wire.PermissionSelection, permit bool) wire.SelectorEdit {
	t.Helper()
	v, e := p.SetSelectorRuleContext(context.Background(), selectorRevision(t, p), wire.SelectorRule{Subject: s, Selection: selection, Permit: permit}, RuleEdit{By: s}, func() error { return nil })
	if e != nil || v.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("edit: %+v %v", v, e)
	}
	return v
}
func TestSelectorsBlocksVersionsAndConsentAdmission(t *testing.T) {
	p, s := testSelectorPolicy(t)
	setTestSelector(t, p, s, testSelection(selectorUse, ""), true)
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
	req := wire.CheckBatchRequest{CollectionAdmission: &wire.PermissionKey{Action: selectorUse, ResourceProfile: selectorTestProfile}, Resources: []wire.ConcreteResource{{Permission: testSelection(selectorUse, "").Permission, Target: testTarget("alpha")}, {Permission: testSelection(selectorUse, "").Permission, Target: testTarget("beta")}}}
	v := p.CheckBatchContext(context.Background(), s, req)
	if v.Outcome != wire.BatchCheckOutcomeChecked || *v.CollectionOutcome != wire.DecisionOutcomePermitted || v.Outcomes[0] != wire.DecisionOutcomeDenied || v.Outcomes[1] != wire.DecisionOutcomePermitted {
		t.Fatal(v)
	}
	effect, e := p.Definitions.PreparePermissionEffect(s, []wire.PermissionSelection{testSelection(selectorUse, "")}, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	consent := p.CheckPermissionEffectContext(context.Background(), effect, "")
	if consent.Outcomes[0] != wire.DecisionOutcomeDenied {
		t.Fatal("broad consent reconsidered block", consent)
	}
	if e = p.Set(s, selectorUse, "name:alpha", true); e != nil {
		t.Fatal(e)
	}
	if d := p.Decide(s, selectorUse, "name:alpha"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("typed block bypass through old API", d)
	}
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), true)
	if e = p.Set(s, selectorUse, "name:alpha", false); e != nil {
		t.Fatal(e)
	}
	if d := p.CheckBatchContext(context.Background(), s, req); d.Outcomes[0] != wire.DecisionOutcomeDenied || *d.CollectionOutcome != wire.DecisionOutcomePermitted {
		t.Fatal("legacy block lost under all", d)
	}
	if e = p.Set(s, selectorUse, "*", false); e != nil {
		t.Fatal(e)
	}
	if d := p.CheckBatchContext(context.Background(), s, req); d.Outcomes[1] != wire.DecisionOutcomePermitted {
		t.Fatal("literal star expanded", d)
	}
	if e = p.Set(s, selectorManage, "account", true); e != nil {
		t.Fatal(e)
	}
	setTestSelector(t, p, s, testSelection(selectorCreate, "alpha"), false)
	if d := p.Decide(s, selectorManage, "account"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("coarse public decision leaked blocked collection", d)
	}
	concrete := wire.ConcreteResource{Permission: testSelection(selectorCreate, "").Permission, Target: testTarget("beta")}
	d := p.CheckLegacyOperationContext(context.Background(), s, wire.LegacyOperationRequest{LegacyAction: selectorManage, LegacyResource: "account", ConcreteOperation: &concrete})
	if d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("concrete beta refused by unrelated alpha block", d)
	}
	concrete.Permission = testSelection(selectorUse, "").Permission
	d = p.CheckLegacyOperationContext(context.Background(), s, wire.LegacyOperationRequest{LegacyAction: selectorManage, LegacyResource: "account", ConcreteOperation: &concrete})
	if d.Outcome != wire.DecisionOutcomeInvalid {
		t.Fatal("manufactured equivalence accepted", d)
	}
}
func TestSelectorsBatchConflictAndSingleSnapshot(t *testing.T) {
	p, s := testSelectorPolicy(t)
	setTestSelector(t, p, s, testSelection(selectorUse, ""), true)
	old := selectorRevision(t, p)
	setTestSelector(t, p, s, testSelection(selectorCreate, ""), true)
	req := wire.CheckBatchRequest{ExpectedRevision: old, Resources: []wire.ConcreteResource{{Permission: testSelection(selectorUse, "").Permission, Target: testTarget("alpha")}}}
	v := p.CheckBatchContext(context.Background(), s, req)
	if v.Outcome != wire.BatchCheckOutcomeConflict || v.Revision == old || len(v.Outcomes) != 0 || v.CollectionOutcome != nil {
		t.Fatal(v)
	}
	req.ExpectedRevision = ""
	req.Resources = append(req.Resources, wire.ConcreteResource{Permission: testSelection(selectorUse, "").Permission, Target: testTarget("beta")})
	before := selectorRevision(t, p)
	changed := false
	p.Clock = func() time.Time {
		if !changed {
			changed = true
			permit := false
			_, e := p.SetSelectorRuleContext(context.Background(), before, wire.SelectorRule{Subject: s, Selection: testSelection(selectorUse, ""), Permit: permit}, RuleEdit{By: s}, func() error { return nil })
			if e != nil {
				t.Error(e)
			}
		}
		return time.Now()
	}
	v = p.CheckBatchContext(context.Background(), s, req)
	if v.Revision != before || v.Outcomes[0] != wire.DecisionOutcomePermitted || v.Outcomes[1] != wire.DecisionOutcomePermitted {
		t.Fatal("mixed snapshot", v)
	}
	p.Clock = nil
	if next := p.CheckBatchContext(context.Background(), s, req); next.Outcomes[0] != wire.DecisionOutcomeDenied || next.Revision == before {
		t.Fatal("next batch missed block", next)
	}
}
func TestSelectorsKnownUnservedRestartAndRetainedRemoval(t *testing.T) {
	p, s := testSelectorPolicy(t)
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), true)
	if e := p.Set(s, selectorUse, "legacy", true); e != nil {
		t.Fatal(e)
	}
	q, e := LoadDecisionPolicyWithDefinitions(p.path, []string{selectorUse, selectorCreate, selectorManage}, testSelectorCatalog(t, false))
	if e != nil {
		t.Fatal("availability invalidated durable state", e)
	}
	if d := q.Decide(s, selectorUse, "legacy"); d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("unrelated legacy unavailable", d)
	}
	read := q.ReadSelectorRuleContext(context.Background(), s, testSelection(selectorUse, "alpha"))
	if read.Outcome != wire.RuleReadOutcomeFound {
		t.Fatal(read)
	}
	v := q.CheckBatchContext(context.Background(), s, wire.CheckBatchRequest{Resources: []wire.ConcreteResource{{Permission: testSelection(selectorUse, "").Permission, Target: testTarget("alpha")}}})
	if v.Outcome != wire.BatchCheckOutcomeUnavailable || len(v.Outcomes) != 0 {
		t.Fatal(v)
	}
	removed, e := q.RemoveSelectorRuleContext(context.Background(), read.Revision, s, read.Record.Rule.Selection, RuleEdit{By: s}, func() error { return nil })
	if e != nil || removed.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(removed, e)
	}
}

func TestSelectorsRetainedReadRemovalNeverPreparesTarget(t *testing.T) {
	p, s := testSelectorPolicy(t)
	binding := p.Definitions.selectors.profiles[selectorTestProfile]
	original := binding.Prepare
	exists := true
	prepared := 0
	binding.Prepare = func(data []byte) ([]byte, error) {
		prepared++
		if !exists {
			return nil, errors.New("requested image was deleted/retargeted")
		}
		return original(data)
	}
	p.Definitions.selectors.profiles[selectorTestProfile] = binding
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), true)
	exists = false
	read := p.ReadSelectorRuleContext(context.Background(), s, testSelection(selectorUse, "alpha"))
	if read.Outcome != wire.RuleReadOutcomeFound {
		t.Fatal(read)
	}
	removed, e := p.RemoveSelectorRuleContext(context.Background(), read.Revision, s, read.Record.Rule.Selection, RuleEdit{By: s}, func() error { return nil })
	if e != nil || removed.Outcome != wire.PolicyEditOutcomeApplied || prepared != 1 {
		t.Fatal("read/removal recaptured target", removed, e, prepared)
	}
}
func TestSelectorsBundleOriginAndReplayAfterRevoke(t *testing.T) {
	p, s := testSelectorPolicy(t)
	v, e := p.ApplyBundleContext(context.Background(), selectorRevision(t, p), s, "example.resources/full-control@1", testSelection(selectorUse, "alpha").Selector, RuleEdit{By: s}, func() error { return nil })
	if e != nil || v.Outcome != wire.PolicyEditOutcomeApplied || v.BundleOrigin == nil || len(v.Current) != 2 {
		t.Fatal(v, e)
	}
	origin := v.BundleOrigin.ID
	setTestSelector(t, p, s, testSelection(selectorCreate, "alpha"), true)
	removed, e := p.RemoveBundleContext(context.Background(), selectorRevision(t, p), s, origin, RuleEdit{By: s}, func() error { return nil })
	if e != nil || removed.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(removed, e)
	}
	req := wire.CheckBatchRequest{Resources: []wire.ConcreteResource{{Permission: testSelection(selectorCreate, "").Permission, Target: testTarget("alpha")}, {Permission: testSelection(selectorUse, "").Permission, Target: testTarget("alpha")}}}
	d := p.CheckBatchContext(context.Background(), s, req)
	if d.Outcomes[0] != wire.DecisionOutcomePermitted || d.Outcomes[1] != wire.DecisionOutcomeNotGranted {
		t.Fatal("origin removal erased independent edit", d)
	}
	effect, e := p.Definitions.PreparePermissionEffect(s, []wire.PermissionSelection{testSelection(selectorUse, "alpha")}, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("a", 32)
	v, e = p.ApplyPermissionEffect(context.Background(), selectorRevision(t, p), effect, RuleEdit{By: s}, id, []string{id}, func() error { return nil })
	if e != nil || v.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(v, e)
	}
	_, e = p.RemoveSelectorRuleContext(context.Background(), v.Revision, s, effect.Selections[0], RuleEdit{By: s}, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	v, e = p.ApplyPermissionEffect(context.Background(), selectorRevision(t, p), effect, RuleEdit{By: s}, id, []string{id}, func() error { return nil })
	if e != nil || v.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatal("completed receipt restored revoked permit", v, e)
	}
}
