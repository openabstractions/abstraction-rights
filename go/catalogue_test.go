package rights

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func clocked(t *testing.T, seed ...string) (*DecisionPolicy, string, *time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	p, err := LoadDecisionPolicy(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	p.Clock = func() time.Time { return now }
	return p, path, &now
}

func TestCatalogueRegistrationConflictRetirementAndBounds(t *testing.T) {
	p, path, now := clocked(t, decisionAction)
	s := subject(t)
	operator := wire.Subject{Account: "operator", Program: s.Program}
	allow := func() error { return nil }
	snapshot, err := p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"noslash", "Upper/name", "owner/", "/name", ".owner/name", "owner/na me", strings.Repeat("o", 65) + "/n"} {
		if r, err := p.EditAction(snapshot.Revision, bad, true, operator, allow); err != nil || r.Outcome != wire.ActionEditOutcomeInvalid || r.Revision != "" {
			t.Fatal(bad, r, err)
		}
	}
	const action = "example.app/export"
	if d := p.Decide(s, action, "x"); d.Outcome != wire.DecisionOutcomeUnknownAction {
		t.Fatal(d)
	}
	if r, err := p.EditAction("stale", action, true, operator, allow); err != nil || r.Outcome != wire.ActionEditOutcomeConflict || r.Revision != snapshot.Revision || r.Current != nil {
		t.Fatal(r, err)
	}
	added, err := p.EditAction(snapshot.Revision, action, true, operator, allow)
	if err != nil || added.Outcome != wire.ActionEditOutcomeApplied || added.Current == nil || added.Current.RegisteredBy != operator || added.Current.RegisteredAt != "2026-09-15T08:00:00.000Z" {
		t.Fatal(added, err)
	}
	if d := p.Decide(s, action, "x"); d.Outcome != wire.DecisionOutcomeNotGranted || d.PolicyRevision != added.Revision {
		t.Fatal("registration granted", d)
	}
	raw, _ := os.ReadFile(path)
	if again, err := p.EditAction(added.Revision, action, true, operator, allow); err != nil || again.Outcome != wire.ActionEditOutcomeApplied || again.Revision != added.Revision {
		t.Fatal(again, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(raw, after) {
		t.Fatal("repeated registration wrote")
	}
	reopened, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	if catalogue, err := reopened.Catalogue(); err != nil || !slices.Equal(catalogue, []string{decisionAction, action}) {
		t.Fatal(catalogue, err)
	}
	if err = p.Set(s, action, "x", true); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadDecisionPolicy(path, []string{"other/seed"}); err != nil {
		t.Fatal("seed change refused a file whose rules name registered actions", err)
	}
	current, _ := p.OperatorSnapshot()
	if r, err := p.EditAction(current.Revision, decisionAction, false, operator, allow); err != nil || r.Outcome != wire.ActionEditOutcomeInvalid {
		t.Fatal("seed retired", r, err)
	}
	retired, err := p.EditAction(current.Revision, action, false, operator, allow)
	if err != nil || retired.Outcome != wire.ActionEditOutcomeApplied || retired.Current != nil {
		t.Fatal(retired, err)
	}
	if d := p.Decide(s, action, "x"); d.Outcome != wire.DecisionOutcomeUnknownAction {
		t.Fatal("retired action decided", d)
	}
	if after, _ := p.OperatorSnapshot(); len(after.Rules) != 0 {
		t.Fatal("retirement kept rules", after.Rules)
	}
	if r, err := p.EditAction(retired.Revision, action, false, operator, allow); err != nil || r.Outcome != wire.ActionEditOutcomeUnknown || r.Revision != retired.Revision {
		t.Fatal(r, err)
	}
	*now = now.Add(time.Minute)
	for i := 1; i < MaxDecisionActions; i++ {
		if err = p.RegisterAction(fmt.Sprintf("bulk/a%02d", i)); err != nil {
			t.Fatal(i, err)
		}
	}
	if err = p.RegisterAction("bulk/over"); err != ErrCatalogueFull {
		t.Fatal("catalogue bound", err)
	}
	full, _ := p.OperatorSnapshot()
	if r, err := p.EditAction(full.Revision, "bulk/over", true, operator, allow); err != nil || r.Outcome != wire.ActionEditOutcomeExhausted || r.Revision != "" {
		t.Fatal(r, err)
	}
}

func TestRuleExpiryAndProvenance(t *testing.T) {
	p, path, now := clocked(t, decisionAction)
	s := subject(t)
	operator := wire.Subject{Account: "operator", Program: s.Program}
	allow := func() error { return nil }
	snapshot, _ := p.OperatorSnapshot()
	permit := true
	for _, edit := range []RuleEdit{{Permit: &permit, By: operator, TTL: -time.Second}, {Permit: &permit, By: operator, TTL: MaxRuleTTL + time.Millisecond},
		{Permit: &permit, By: operator, TTL: time.Microsecond}, {Permit: &permit, By: operator, Why: strings.Repeat("w", MaxRuleWhy+1)},
		{Permit: &permit, By: operator, Why: "bad\n"}, {By: operator, Why: "revoke with reason"}} {
		if r, err := p.ChangeRule(snapshot.Revision, s, decisionAction, "x", edit, allow); err != nil || r.Outcome != wire.PolicyEditOutcomeInvalid {
			t.Fatal(edit, r, err)
		}
	}
	grant, err := p.ChangeRule(snapshot.Revision, s, decisionAction, "x", RuleEdit{Permit: &permit, By: operator, TTL: time.Hour, Why: "session", Exact: true}, allow)
	if err != nil || grant.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(grant, err)
	}
	read := p.ReadRule(s, decisionAction, "x")
	if read.Outcome != wire.RuleReadOutcomeFound || read.Revision != grant.Revision || read.Record == nil {
		t.Fatal(read)
	}
	if r := *read.Record; r.SetBy != operator || r.SetAt != "2026-09-15T08:00:00.000Z" || r.Why != "session" || r.Expires != "2026-09-15T09:00:00.000Z" {
		t.Fatal(r)
	}
	if same, err := p.ChangeRule(grant.Revision, s, decisionAction, "x", RuleEdit{Permit: &permit, By: operator}, allow); err != nil || same.Revision != grant.Revision {
		t.Fatal("unexpired same-permit SetRule wrote", same, err)
	}
	*now = now.Add(time.Hour)
	if d := p.Decide(s, decisionAction, "x"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("expired rule decided", d)
	}
	if r := p.ReadRule(s, decisionAction, "x"); r.Outcome != wire.RuleReadOutcomeExpired || r.Revision != grant.Revision {
		t.Fatal(r)
	}
	if err = p.Set(s, decisionAction, "other", false); err != nil {
		t.Fatal(err)
	}
	if r := p.ReadRule(s, decisionAction, "x"); r.Outcome != wire.RuleReadOutcomeUnknown {
		t.Fatal("write kept expired rule", r)
	}
	native := p.ReadRule(s, decisionAction, "other")
	if native.Outcome != wire.RuleReadOutcomeFound || native.Record.SetBy != p.native || native.Record.Expires != "" || native.Record.Why != "" {
		t.Fatal("native provenance", native)
	}
	if d := p.Decide(s, decisionAction, "other"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatal(d)
	}
	data, _ := os.ReadFile(path)
	legacy := bytes.Replace(data, []byte(DecisionProfile), []byte("rights-decisions@1"), 1)
	if err = os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadDecisionPolicy(path, []string{decisionAction}); err == nil {
		t.Fatal("version 1 profile accepted")
	}
}
