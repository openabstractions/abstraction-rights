package rights

import (
	"context"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// breakComparison makes the test profile's comparison panic.
func breakComparison(p *DecisionPolicy) {
	profiles := p.Definitions.selectors.profiles
	profile := profiles[selectorTestProfile]
	profile.Equal = func([]byte, []byte) bool { panic("broken comparison") }
	profiles[selectorTestProfile] = profile
}

func useResource(name string) wire.ConcreteResource {
	return wire.ConcreteResource{Permission: testSelection(selectorUse, "").Permission, Target: testTarget(name)}
}

// refusedBatch is the RIGHTS-R19 unavailable shape: no outcomes, no
// collection outcome and no revision.
func refusedBatch(v wire.BatchDecision) bool {
	return v.Outcome == wire.BatchCheckOutcomeUnavailable && v.Revision == "" && len(v.Outcomes) == 0 && v.CollectionOutcome == nil
}

// RIGHTS-R26: a Block whose target comparison cannot be evaluated refuses the
// whole reply as unavailable, in every evaluator that reads a Block, with the
// refusal shape of RIGHTS-R19, RIGHTS-E2 and RIGHTS-O14. Before the R26 fix the
// comparison panic escaped; before this fix the refusal was a per-item
// unavailable outcome carrying a revision.
func TestSelectorsUnevaluableBlockRefuses(t *testing.T) {
	t.Run("typed block in a batch", func(t *testing.T) {
		p, s := testSelectorPolicy(t)
		setTestSelector(t, p, s, testSelection(selectorUse, ""), true)
		setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
		breakComparison(p)
		v := p.CheckBatchContext(context.Background(), s, wire.CheckBatchRequest{Resources: []wire.ConcreteResource{useResource("beta")}})
		if !refusedBatch(v) {
			t.Fatalf("unevaluable block did not refuse the batch: %+v", v)
		}
	})
	t.Run("collection admission with an unevaluable item", func(t *testing.T) {
		p, s := testSelectorPolicy(t)
		setTestSelector(t, p, s, testSelection(selectorUse, ""), true)
		setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
		breakComparison(p)
		key := testSelection(selectorUse, "").Permission
		v := p.CheckBatchContext(context.Background(), s, wire.CheckBatchRequest{CollectionAdmission: &key, Resources: []wire.ConcreteResource{useResource("beta")}})
		if !refusedBatch(v) {
			t.Fatalf("unevaluable block did not refuse collection admission: %+v", v)
		}
	})
	t.Run("permit sorted before the block", func(t *testing.T) {
		p, s := testSelectorPolicy(t)
		setTestSelector(t, p, s, testSelection(selectorUse, "aa"), true)
		setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
		breakComparison(p)
		v := p.CheckBatchContext(context.Background(), s, wire.CheckBatchRequest{Resources: []wire.ConcreteResource{useResource("aa")}})
		if !refusedBatch(v) {
			t.Fatalf("unevaluable block did not refuse the batch: %+v", v)
		}
	})
	t.Run("consent admission on one target", func(t *testing.T) {
		p, s := testSelectorPolicy(t)
		setTestSelector(t, p, s, testSelection(selectorUse, ""), true)
		setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
		effect, e := p.Definitions.PreparePermissionEffect(s, []wire.PermissionSelection{testSelection(selectorUse, "beta")}, "", nil)
		if e != nil {
			t.Fatal(e)
		}
		breakComparison(p)
		v := p.CheckPermissionEffectContext(context.Background(), effect, "")
		if !refusedBatch(v) {
			t.Fatalf("unevaluable block did not refuse consent admission: %+v", v)
		}
	})
	t.Run("exact block in a typed decision", func(t *testing.T) {
		p, s := testSelectorPolicy(t)
		setTestSelector(t, p, s, testSelection(selectorUse, ""), true)
		if e := p.Set(s, selectorUse, "name:alpha", false); e != nil {
			t.Fatal(e)
		}
		breakComparison(p)
		v := p.CheckBatchContext(context.Background(), s, wire.CheckBatchRequest{Resources: []wire.ConcreteResource{useResource("beta")}})
		if !refusedBatch(v) {
			t.Fatalf("unevaluable exact block did not refuse the batch: %+v", v)
		}
	})
	t.Run("typed block in a legacy decision and its explanation", func(t *testing.T) {
		p, s := testSelectorPolicy(t)
		if e := p.Set(s, selectorUse, "name:beta", true); e != nil {
			t.Fatal(e)
		}
		setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
		breakComparison(p)
		d := p.CheckLegacyOperationContext(context.Background(), s, wire.LegacyOperationRequest{LegacyAction: selectorUse, LegacyResource: "name:beta"})
		if d.Outcome != wire.DecisionOutcomeUnavailable || d.PolicyRevision != "" {
			t.Fatalf("unevaluable typed block did not refuse the legacy decision: %+v", d)
		}
		x := p.ExplainForContext(context.Background(), s, selectorUse, "name:beta")
		if x.Outcome != wire.DecisionOutcomeUnavailable || x.PolicyRevision != "" || x.Source != nil || x.DefaultName != "" {
			t.Fatalf("unevaluable typed block did not refuse the explanation: %+v", x)
		}
	})
}
