package authorization

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
)

// RIGHTS-R26 with RIGHTS-R19, RIGHTS-E2 and RIGHTS-O14: a Block whose target
// comparison cannot be evaluated refuses the whole reply as unavailable, with
// no outcomes, revision, source or name. The real Go client accepts each reply
// and reads unavailable. A per-item unavailable outcome carrying a revision is
// rejected by the client as an inconsistent reply.
func TestSelectorUnevaluableBlockRefusesThroughClient(t *testing.T) {
	var broken atomic.Bool
	equal := func(a, b []byte) bool {
		if broken.Load() {
			panic("broken comparison")
		}
		return bytes.Equal(a, b)
	}
	key := wire.PermissionKey{Action: nativeAction, ResourceProfile: nativeProfile}
	links := []rights.LegacyEquivalence{{Action: nativeAction, Permission: key, Mode: "named-read@1", Concrete: func(resource string) ([]byte, bool) {
		name, ok := strings.CutPrefix(resource, "name:")
		if !ok || name == "" {
			return nil, false
		}
		return nativeTarget("captured", name), true
	}}}
	subject := nativeSubject(t)
	enforcer := func(_ context.Context, peer *identity.Peer, action, _ string) bool {
		actual, err := client.SubjectFromPeer(peer)
		return err == nil && actual == subject && action == nativeAction
	}
	_, endpoint, s := selectorNativeFixtureWith(t, equal, links, enforcer)
	reader, operator, explainer := client.New(endpoint), client.NewSelectorOperator(endpoint), client.NewOperator(endpoint)
	ctx := context.Background()

	rules, err := operator.ListSelectorRulesContext(ctx, "", 64)
	if err != nil {
		t.Fatal(err)
	}
	all, err := operator.SetSelectorRuleContext(ctx, rules.Revision, wire.SelectorRule{Subject: s, Selection: nativeSelection(wire.ResourceSelectorKindAll, ""), Permit: true}, 0, "")
	if err != nil || all.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(all, err)
	}
	block, err := operator.SetSelectorRuleContext(ctx, all.Revision, wire.SelectorRule{Subject: s, Selection: nativeSelection(wire.ResourceSelectorKindOne, "alpha"), Permit: false}, 0, "block alpha")
	if err != nil || block.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(block, err)
	}
	request := wire.CheckBatchRequest{CollectionAdmission: &key, Resources: []wire.ConcreteResource{{Permission: key, Target: nativeTarget("captured", "beta")}}}
	legacy := wire.LegacyOperationRequest{LegacyAction: nativeAction, LegacyResource: "name:beta"}

	// The same journey evaluates while the comparison works.
	if v, err := reader.CheckBatchForContext(ctx, s, request); err != nil || v.Outcome != wire.BatchCheckOutcomeChecked || v.Outcomes[0] != wire.DecisionOutcomePermitted {
		t.Fatal("evaluable batch", v, err)
	}
	if d, err := reader.CheckLegacyOperationForContext(ctx, s, legacy); err != nil || d.PolicyRevision == "" {
		t.Fatal("evaluable legacy decision", d, err)
	}

	broken.Store(true)
	v, err := reader.CheckBatchForContext(ctx, s, request)
	if err != nil || v.Outcome != wire.BatchCheckOutcomeUnavailable || v.Revision != "" || len(v.Outcomes) != 0 || v.CollectionOutcome != nil {
		t.Errorf("batch: %+v %v", v, err)
	}
	d, err := reader.CheckLegacyOperationForContext(ctx, s, legacy)
	if err != nil || d.Outcome != wire.DecisionOutcomeUnavailable || d.PolicyRevision != "" {
		t.Errorf("legacy operation: %+v %v", d, err)
	}
	d, err = reader.DecideForContext(ctx, s, nativeAction, "name:beta")
	if err != nil || d.Outcome != wire.DecisionOutcomeUnavailable || d.PolicyRevision != "" {
		t.Errorf("legacy decision: %+v %v", d, err)
	}
	x, err := explainer.ExplainForContext(ctx, s, nativeAction, "name:beta")
	if err != nil || x.Outcome != wire.DecisionOutcomeUnavailable || x.PolicyRevision != "" || x.Source != nil || x.DefaultName != "" {
		t.Errorf("explanation: %+v %v", x, err)
	}
}
