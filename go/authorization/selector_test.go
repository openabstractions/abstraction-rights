package authorization

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
)

const nativeProfile = "example.native/targets@1"
const nativeAction = "example.native/read"

func nativeTarget(op, name string) []byte {
	return wire.EncodeRequest(&wire.Request{Op: op, Name: name})
}
func nativeSelection(kind wire.ResourceSelectorKind, name string) wire.PermissionSelection {
	s := wire.PermissionSelection{Permission: wire.PermissionKey{Action: nativeAction, ResourceProfile: nativeProfile}, Selector: wire.ResourceSelector{Kind: kind}}
	if kind == wire.ResourceSelectorKindOne {
		s.Selector.Target = nativeTarget("request", name)
	}
	return s
}
func selectorNativeFixture(t *testing.T) (*rights.DecisionPolicy, *client.Client, *client.SelectorOperator, wire.Subject) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("native Program evidence unavailable")
	}
	definition := wire.SelectorPermissionDefinition{Definition: wire.PermissionDefinition{Action: nativeAction, OwnerContract: "example.native/reader@2", Operations: []string{"example.native/reader@2#Read"}, ResourceProfile: nativeProfile, ResourceType: "example.Target", EnforcedBy: []string{"example.native/reader@2"}, Disclosure: "Read test target", Lifecycle: "Captured test target", FirstUse: wire.PermissionFirstUseNone, Served: true}, Label: "Read", SupportedSelectors: []wire.ResourceSelectorKind{wire.ResourceSelectorKindOne, wire.ResourceSelectorKindAll}, FirstUseSelectors: []wire.ResourceSelectorKind{wire.ResourceSelectorKindOne, wire.ResourceSelectorKindAll}, Collection: "example.native/targets@1", AllEffect: "Every current and future test target", RequestType: "example.Request"}
	base, err := rights.NewDefinitionCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := base.WithSelectors([]wire.SelectorPermissionDefinition{definition}, map[string]rights.ResourceProfile{nativeProfile: {AllowAll: true, Prepare: func(raw []byte) ([]byte, error) {
		v, err := wire.DecodeRequest(raw)
		if err != nil || v.Op != "request" || v.Name == "" {
			return nil, errors.New("captured evidence is not a request")
		}
		return nativeTarget("captured", v.Name), nil
	}, Validate: func(raw []byte) bool {
		v, err := wire.DecodeRequest(raw)
		return err == nil && v.Op == "captured" && v.Name != "" && bytes.Equal(raw, nativeTarget(v.Op, v.Name))
	}, Equal: bytes.Equal}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := rights.LoadDecisionPolicyWithDefinitions(filepath.Join(t.TempDir(), "rights.json"), []string{nativeAction}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	s := nativeSubject(t)
	endpoint := listen.Endpoint(fmt.Sprintf("rights-selector-%d-%d", os.Getpid(), serial.Add(1)))
	h, err := Listen(endpoint, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.EnableOperator(func(context.Context, *identity.Peer) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = h.EnableSelectorEnforcer(func(_ context.Context, peer *identity.Peer, selection wire.PermissionSelection) bool {
		actual, err := client.SubjectFromPeer(peer)
		return err == nil && actual == s && selection.Permission == definitionKey(definition)
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background()) }()
	t.Cleanup(func() {
		h.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("host did not drain")
		}
	})
	return p, client.New(endpoint), client.NewSelectorOperator(endpoint), s
}
func definitionKey(d wire.SelectorPermissionDefinition) wire.PermissionKey {
	return wire.PermissionKey{Action: d.Definition.Action, ResourceProfile: d.Definition.ResourceProfile}
}
func TestSelectorNativeDiscoveryEditsAndGuardedBatch(t *testing.T) {
	_, reader, operator, subject := selectorNativeFixture(t)
	ctx := context.Background()
	defs, err := reader.ListPermissionDefinitionsContext(ctx, "", 1)
	if err != nil || defs.Outcome != wire.PolicyPageOutcomePage || len(defs.Definitions) != 1 || !defs.Complete {
		t.Fatal(defs, err)
	}
	rules, err := operator.ListSelectorRulesContext(ctx, "", 64)
	if err != nil {
		t.Fatal(err)
	}
	all := nativeSelection(wire.ResourceSelectorKindAll, "")
	edit, err := operator.SetSelectorRuleContext(ctx, rules.Revision, wire.SelectorRule{Subject: subject, Selection: all, Permit: true}, 0, "native test")
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	one := nativeSelection(wire.ResourceSelectorKindOne, "alpha")
	block, err := operator.SetSelectorRuleContext(ctx, edit.Revision, wire.SelectorRule{Subject: subject, Selection: one, Permit: false}, 0, "block alpha")
	if err != nil || block.Outcome != wire.PolicyEditOutcomeApplied || len(block.Current) != 1 {
		t.Fatal(block, err)
	}
	key := all.Permission
	request := wire.CheckBatchRequest{ExpectedRevision: block.Revision, CollectionAdmission: &key, Resources: []wire.ConcreteResource{{Permission: key, Target: nativeTarget("captured", "alpha")}, {Permission: key, Target: nativeTarget("captured", "beta")}}}
	decision, err := reader.CheckBatchForContext(ctx, subject, request)
	if err != nil || decision.Outcome != wire.BatchCheckOutcomeChecked || *decision.CollectionOutcome != wire.DecisionOutcomePermitted || decision.Outcomes[0] != wire.DecisionOutcomeDenied || decision.Outcomes[1] != wire.DecisionOutcomePermitted {
		t.Fatal(decision, err)
	}
	request.ExpectedRevision = edit.Revision
	decision, err = reader.CheckBatchForContext(ctx, subject, request)
	if err != nil || decision.Outcome != wire.BatchCheckOutcomeConflict || len(decision.Outcomes) != 0 {
		t.Fatal(decision, err)
	}
	// Apps cannot submit captured target evidence through a direct request.
	request.ExpectedRevision = ""
	decision, err = reader.CheckBatchContext(ctx, request)
	if err != nil || decision.Outcome != wire.BatchCheckOutcomeInvalid {
		t.Fatal(decision, err)
	}
	canonical := block.Current[0].Rule.Selection
	retained, err := operator.ReadSelectorRuleContext(ctx, subject, canonical)
	if err != nil || retained.Outcome != wire.RuleReadOutcomeFound {
		t.Fatal(retained, err)
	}
	removed, err := operator.RemoveSelectorRuleContext(ctx, retained.Revision, subject, canonical)
	if err != nil || removed.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(removed, err)
	}
	request.ExpectedRevision = removed.Revision
	decision, err = reader.CheckBatchForContext(ctx, subject, request)
	if err != nil || decision.Outcomes[0] != wire.DecisionOutcomePermitted {
		t.Fatal(decision, err)
	}
	stale, err := operator.SetSelectorRuleContext(ctx, removed.Revision, wire.SelectorRule{Subject: subject, Selection: one, Permit: true}, 0, "")
	if err != nil || stale.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(stale, err)
	}
	stale, err = operator.RemoveSelectorRuleContext(ctx, removed.Revision, subject, canonical)
	if err != nil || stale.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatal(stale, err)
	}
}
