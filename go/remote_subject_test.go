package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRemoveRemoteSubjectMixedStateAndReplay(t *testing.T) {
	p, _ := testSelectorPolicy(t)
	actor := p.native
	a := remoteTestSubject(actor.Account, "a")
	b := remoteTestSubject(actor.Account, "b")
	c := remoteTestSubject("other-account", "a")
	allow := func() error { return nil }
	for _, s := range []wire.Subject{a, b, c, actor} {
		for _, permit := range []bool{true, false} {
			resource := "permit"
			if !permit {
				resource = "deny"
			}
			if err := p.Set(s, selectorUse, resource, permit); err != nil {
				t.Fatal(err)
			}
		}
		setRemovalSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
	}
	// Both the legacy and typed completion owners must remember old approvals.
	id1, id2 := strings.Repeat("1", 32), strings.Repeat("2", 32)
	permit := true
	rules := []wire.PolicyRule{{Subject: a, Action: selectorUse, Resource: "answered", Permit: true}}
	if v, err := p.ApplyFirstUseAllow(context.Background(), selectorRevision(t, p), rules, RuleEdit{Permit: &permit, By: actor}, id1, []string{id1}, allow); err != nil || v.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(v, err)
	}
	effect, err := p.Definitions.PreparePermissionEffect(a, []wire.PermissionSelection{testSelection(selectorCreate, "beta")}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := p.ApplyPermissionEffect(context.Background(), selectorRevision(t, p), effect, RuleEdit{By: actor}, id2, []string{id2}, allow); err != nil || v.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(v, err)
	}
	// A bundle origin can remain referenced by another subject. Unrelated
	// expired rows and unreferenced metadata must also survive this exact edit.
	v, err := p.ApplyBundleContext(context.Background(), selectorRevision(t, p), a, "example.resources/full-control@1", testSelection(selectorUse, "bundle").Selector, RuleEdit{By: actor}, allow)
	if err != nil || v.BundleOrigin == nil {
		t.Fatal(v, err)
	}
	shared := v.BundleOrigin.ID
	v, err = p.ApplyBundleContext(context.Background(), selectorRevision(t, p), a, "example.resources/full-control@1", testSelection(selectorUse, "only-a").Selector, RuleEdit{By: actor}, allow)
	if err != nil || v.BundleOrigin == nil {
		t.Fatal(v, err)
	}
	onlyA := v.BundleOrigin.ID
	if err = p.change(func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		for _, r := range f.SelectorRules {
			if r.Subject == a && r.OriginID == shared {
				r.Subject = b
				f.SelectorRules = append(f.SelectorRules, r)
			}
		}
		for i := range f.Rules {
			if f.Rules[i].Resource == "deny" {
				f.Rules[i].Expires = stamp(time.Unix(946684800, 0))
			}
		}
		for i := range f.SelectorRules {
			if !f.SelectorRules[i].Permit {
				f.SelectorRules[i].Expires = stamp(time.Unix(946684800, 0))
			}
		}
		f.BundleOrigins = append(f.BundleOrigins, storedBundleOrigin{ID: "unused", Expansion: f.BundleOrigins[0].Expansion})
		sortSelectorState(&f)
		return json.Marshal(f)
	}); err != nil {
		t.Fatal(err)
	}
	before, revision, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	expected := before
	expected.Rules = slices.DeleteFunc(slices.Clone(before.Rules), func(r decisionRule) bool { return r.Subject == a })
	expected.SelectorRules = slices.DeleteFunc(slices.Clone(before.SelectorRules), func(r selectorRule) bool { return r.Subject == a })
	expected.BundleOrigins = slices.DeleteFunc(slices.Clone(before.BundleOrigins), func(o storedBundleOrigin) bool { return o.ID == onlyA })
	changed := 0
	p.OnChange(func() { changed++ })
	// Discard the successful reply and reload the real CAS file.
	if _, err = p.RemoveRemoteSubjectContext(context.Background(), revision, a, allow); err != nil {
		t.Fatal(err)
	}
	after, newRevision, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(after)
	if !bytes.Equal(want, got) || changed != 1 || newRevision == revision {
		t.Fatalf("wrong exact removal: %s / %s, notifications %d", got, want, changed)
	}
	q, err := LoadDecisionPolicyWithDefinitions(p.path, []string{selectorUse, selectorCreate, selectorManage}, p.Definitions)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := q.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	typedRevision, typed, err := q.SelectorSnapshotContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Revision != typedRevision {
		t.Fatal("split reconciliation")
	}
	for _, r := range legacy.Rules {
		if r.Subject == a {
			t.Fatal("legacy survived")
		}
	}
	for _, r := range typed {
		if r.Rule.Subject == a {
			t.Fatal("typed survived")
		}
	}
	if v, err := q.ApplyFirstUseAllow(context.Background(), typedRevision, rules, RuleEdit{Permit: &permit, By: actor}, id1, []string{id1}, allow); err != nil || v.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatal("legacy replay", v, err)
	}
	if v, err := q.ApplyPermissionEffect(context.Background(), typedRevision, effect, RuleEdit{By: actor}, id2, []string{id2}, allow); err != nil || v.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatal("typed replay", v, err)
	}
	if v, err := q.RemoveRemoteSubjectContext(context.Background(), revision, a, allow); err != nil || v.Outcome != wire.PolicyEditOutcomeConflict || v.Revision != typedRevision {
		t.Fatal("lost reply revision", v, err)
	}
	data, _ := os.ReadFile(p.path)
	if v, err := p.RemoveRemoteSubjectContext(context.Background(), typedRevision, a, allow); err != nil || v.Outcome != wire.PolicyEditOutcomeApplied || v.Revision != typedRevision {
		t.Fatal("empty no-op", v, err)
	}
	unchanged, _ := os.ReadFile(p.path)
	if !bytes.Equal(data, unchanged) || changed != 1 {
		t.Fatal("no-op changed file or notified")
	}
}

func TestRemoveRemoteSubjectRefusals(t *testing.T) {
	p, _ := testSelectorPolicy(t)
	actor := p.native
	s := remoteTestSubject(actor.Account, "a")
	if err := p.Set(s, selectorUse, "legacy", true); err != nil {
		t.Fatal(err)
	}
	setRemovalSelector(t, p, s, testSelection(selectorUse, "alpha"), true)
	revision := selectorRevision(t, p)
	before, _ := os.ReadFile(p.path)
	notifications := 0
	p.OnChange(func() { notifications++ })
	denied := errors.New("Remove intent withdrawn")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		expected  string
		subject   wire.Subject
		authorize func() error
		outcome   wire.PolicyEditOutcome
	}{
		{"stale", context.Background(), "stale", s, func() error { return nil }, wire.PolicyEditOutcomeConflict},
		{"nil", context.Background(), revision, s, nil, wire.PolicyEditOutcomeUnavailable},
		{"denied", context.Background(), revision, s, func() error { return denied }, wire.PolicyEditOutcomeUnavailable},
		{"cancelled", ctx, revision, s, func() error { t.Fatal("cancelled admission ran"); return nil }, wire.PolicyEditOutcomeUnavailable},
		{"native", context.Background(), revision, actor, nil, wire.PolicyEditOutcomeInvalid},
		{"foreign account", context.Background(), revision, remoteTestSubject("other", "a"), nil, wire.PolicyEditOutcomeInvalid},
		{"wildcard", context.Background(), revision, wire.Subject{Account: actor.Account, Program: "remote:*"}, nil, wire.PolicyEditOutcomeInvalid},
		{"empty", context.Background(), revision, wire.Subject{}, nil, wire.PolicyEditOutcomeInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := p.RemoveRemoteSubjectContext(tc.ctx, tc.expected, tc.subject, tc.authorize)
			if v.Outcome != tc.outcome {
				t.Fatal(v)
			}
			data, _ := os.ReadFile(p.path)
			if !bytes.Equal(before, data) || notifications != 0 {
				t.Fatal("refusal changed state")
			}
		})
	}
}

func remoteTestSubject(account, digit string) wire.Subject {
	return wire.Subject{Account: account, Program: "remote:" + strings.Repeat(digit, 64)}
}

func setRemovalSelector(t *testing.T, p *DecisionPolicy, s wire.Subject, selection wire.PermissionSelection, permit bool) {
	t.Helper()
	v, err := p.SetSelectorRuleContext(context.Background(), selectorRevision(t, p), wire.SelectorRule{Subject: s, Selection: selection, Permit: permit}, RuleEdit{By: p.native}, func() error { return nil })
	if err != nil || v.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(v, err)
	}
}

func TestRemoteSubjectMatchesOnlyExactRuleAndNoIdentityKeys(t *testing.T) {
	p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "policy.json"), []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	s := remoteTestSubject(subject(t).Account, "a")
	if err = p.Set(s, decisionAction, "content", true); err != nil {
		t.Fatal(err)
	}
	if got := p.Decide(s, decisionAction, "content"); got.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal(got)
	}
	for _, other := range []wire.Subject{remoteTestSubject(s.Account, "b"), remoteTestSubject("other", "a"), subject(t)} {
		if p.Decide(other, decisionAction, "content").Outcome == wire.DecisionOutcomePermitted {
			t.Fatal("cross-subject grant", other)
		}
	}
	for _, r := range []string{"other", "content/*"} {
		if p.Decide(s, decisionAction, r).Outcome == wire.DecisionOutcomePermitted {
			t.Fatal(r)
		}
	}
	poison := func(string) string { t.Fatal("remote consulted native file identity"); return "same" }
	if !sameTarget(decisionRule{Subject: s, Action: decisionAction, Resource: "content"}, s, decisionAction, "content", poison) ||
		sameTarget(decisionRule{Subject: subject(t)}, s, "", "", poison) {
		t.Fatal("kind boundary")
	}
	reopened, err := LoadDecisionPolicy(p.path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Decide(s, decisionAction, "content").Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("remote rule did not roundtrip")
	}
	if err = p.Set(s, decisionAction, "content", false); err != nil {
		t.Fatal(err)
	}
	if p.Decide(s, decisionAction, "content").Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("deny lost")
	}
	if err = p.Revoke(s, decisionAction, "content"); err != nil {
		t.Fatal(err)
	}
	if p.Decide(s, decisionAction, "content").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("revocation lost")
	}
	if err = os.WriteFile(p.path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.Decide(s, decisionAction, "content").Outcome != wire.DecisionOutcomeUnavailable {
		t.Fatal("outage granted")
	}
}

func TestRemoteSubjectGetsNoAccountDefaultsAndCannotBeAuthorityActor(t *testing.T) {
	p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "policy.json"), defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	local := subject(t)
	s := remoteTestSubject(local.Account, "a")
	calls := 0
	if err = p.ConfigureDefaults(local.Account, testAccountDefaults(), func(wire.Subject) bool { calls++; return false }); err != nil {
		t.Fatal(err)
	}
	if p.Decide(s, ActionQuestionAsk, ResourceAccount).Outcome != wire.DecisionOutcomeNotGranted || calls != 0 {
		t.Fatal("default consulted", calls)
	}
	if err = p.ConfigureDefaults(local.Account, testAccountDefaults(), nil); err != nil {
		t.Fatal(err)
	}
	if p.Decide(s, ActionQuestionAsk, ResourceAccount).Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("nil exclusion granted")
	}
	if validStoredActor(s) {
		t.Fatal("remote actor accepted")
	}
	if _, err = normalizeActor(s); err == nil {
		t.Fatal("remote authority normalized")
	}
	if err = p.Set(s, ActionQuestionAsk, ResourceAccount, true); err != nil {
		t.Fatal(err)
	}
	f, _, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	f.Rules[0].SetBy = s
	raw, _ := json.Marshal(f)
	if _, err = p.decodeDecision(raw); err == nil {
		t.Fatal("remote setter loaded")
	}
	permit := true
	if err = p.refuseHolder(s, MetaAnswerAction, MetaScopeApps, &permit); err == nil {
		t.Fatal("remote holder")
	}
	for _, text := range []string{"remote:*", "remote:" + strings.Repeat("A", 64), "remote:" + strings.Repeat("a", 63), "remote:" + strings.Repeat("a", 64) + "/local"} {
		if _, err = NormalizeDecisionSubject(wire.Subject{Account: local.Account, Program: text}); err == nil {
			t.Fatal("malformed remote", text)
		}
	}
}

func TestRemoteSubjectSelectorsRejectAllAndIgnoreBroadPredicates(t *testing.T) {
	p, actor := testSelectorPolicy(t)
	s := remoteTestSubject(actor.Account, "a")
	selection := testSelection(selectorUse, "alpha")
	edit, err := p.SetSelectorRuleContext(context.Background(), selectorRevision(t, p), wire.SelectorRule{Subject: s, Selection: selection, Permit: true}, RuleEdit{By: actor}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	edit, err = p.SetSelectorRuleContext(context.Background(), selectorRevision(t, p), wire.SelectorRule{Subject: s, Selection: testSelection(selectorUse, ""), Permit: true}, RuleEdit{By: actor}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeInvalid {
		t.Fatal("remote All stored", edit, err)
	}
	profile := p.Definitions.selectors.profiles[selectorTestProfile]
	profile.Equal = func([]byte, []byte) bool { t.Fatal("remote called non-exact predicate"); return true }
	p.Definitions.selectors.profiles[selectorTestProfile] = profile
	f, rev, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want wire.DecisionOutcome
	}{{"alpha", wire.DecisionOutcomePermitted}, {"beta", wire.DecisionOutcomeNotGranted}} {
		got, ok := p.typedDecision(f, rev, s, selection.Permission, testTarget(tc.name), false, time.Now())
		if !ok || got != tc.want {
			t.Fatal(tc.name, got, ok)
		}
	}
	if got, _ := p.typedDecision(f, rev, s, selection.Permission, nil, true, time.Now()); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("All admitted", got)
	}
	// A poisoned in-memory All rule still cannot grant a remote collection.
	f.SelectorRules = append(f.SelectorRules, selectorRule{Subject: s, Selection: testSelection(selectorUse, ""), Permit: true, SetBy: actor})
	if got, _ := p.typedDecision(f, rev, s, selection.Permission, testTarget("beta"), false, time.Now()); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("wildcard matched", got)
	}
}
