package rights

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestDecisionCacheCatalogueFreezeUsesCurrentRevisionForConditionalEdit(t *testing.T) {
	p, subject := testSelectorPolicy(t)
	// Runtime composition reads known grammar before freezing actual receiving
	// support. The policy file itself is unchanged by that catalogue replacement.
	p.Definitions = testSelectorCatalog(t, false)
	if err := p.Set(subject, selectorUse, "name:alpha", true); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	p.Definitions = testSelectorCatalog(t, true)
	current, err := p.OperatorSnapshot()
	if err != nil || current.Revision == initial.Revision {
		t.Fatal("unchanged policy bytes retained the pre-freeze revision", current, initial, err)
	}
	after, err := os.ReadFile(p.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("catalogue freeze changed policy bytes", err)
	}
	definitionRevision, _, _, err := p.DefinitionSnapshotContext(context.Background())
	if err != nil || definitionRevision != current.Revision {
		t.Fatal("public definition and legacy policy snapshots disagree", definitionRevision, current.Revision, err)
	}
	permit := false
	edited, err := p.ChangeRule(current.Revision, subject, selectorUse, "name:alpha", RuleEdit{By: subject, Permit: &permit}, func() error { return nil })
	if err != nil || edited.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal("immediate conditional edit conflicted with the returned current revision", edited, err)
	}
	decision := p.DecideContext(context.Background(), subject, selectorUse, "name:alpha")
	if decision.Outcome != wire.DecisionOutcomeDenied || decision.PolicyRevision != edited.Revision {
		t.Fatal("decision and edit revisions disagree", decision, edited)
	}
}

func TestDecodedStateRetainsBoundedReuseWithinDefinitionDigest(t *testing.T) {
	var cache decodedState
	data := []byte("unchanged fixture bytes")
	cache.put(data, decisionFile{}, "revision-before", "definitions-before")
	if _, revision, ok := cache.get(data, "definitions-before"); !ok || revision != "revision-before" {
		t.Fatal("identical bytes and definitions missed bounded reuse", revision, ok)
	}
	if _, _, ok := cache.get(data, "definitions-after"); ok {
		t.Fatal("changed definition digest reused a stale decoded revision")
	}
	cache.mu.Lock()
	cache.read = time.Now().Add(-StoredKeyReuse)
	cache.mu.Unlock()
	if _, _, ok := cache.get(data, "definitions-before"); ok {
		t.Fatal("cache reuse exceeded the existing identity budget")
	}
}
