package rights

import (
	"context"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// RIGHTS-R16, RIGHTS-O10: an enrollment asked at first use is completed as
// the operator UI writes it, with exactly MetaRuleLapse and durable proof;
// any other lapse, a lapse on an ordinary permit, and a holder the host
// refuses are invalid.
func TestOperatorAllowWritesTheEnrollmentWithItsLapse(t *testing.T) {
	f := newMetaFixture(t)
	permit := true
	meta := []wire.PolicyRule{{Subject: f.holder, Action: MetaAnswerAction, Resource: MetaScopeApps, Permit: true}}
	ordinary := []wire.PolicyRule{{Subject: f.appA, Action: decisionAction, Resource: "hf", Permit: true}}
	for _, c := range []struct {
		rules []wire.PolicyRule
		ttl   time.Duration
	}{{meta, 0}, {meta, time.Hour}, {ordinary, MetaRuleLapse}} {
		edit, err := f.p.ApplyFirstUseAllow(context.Background(), f.revision(t), c.rules, RuleEdit{Permit: &permit, By: f.panel, Exact: true, TTL: c.ttl}, operatorQ1, []string{operatorQ1}, func() error { return nil })
		if err != nil || edit.Outcome != wire.PolicyEditOutcomeInvalid {
			t.Fatalf("%s with %v: %+v %v", c.rules[0].Action, c.ttl, edit, err)
		}
	}
	f.p.MetaHolder = func(s wire.Subject) error {
		if s.Program == f.appB.Program {
			return ErrMetaTarget
		}
		return nil
	}
	refused := []wire.PolicyRule{{Subject: f.appB, Action: MetaAnswerAction, Resource: MetaScopeApps, Permit: true}}
	if edit, err := f.p.ApplyFirstUseAllow(context.Background(), f.revision(t), refused, RuleEdit{Permit: &permit, By: f.panel, Exact: true, TTL: MetaRuleLapse}, operatorQ2, []string{operatorQ2}, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeInvalid {
		t.Fatalf("a refused holder was enrolled: %+v %v", edit, err)
	}
	edit, err := f.p.ApplyFirstUseAllow(context.Background(), f.revision(t), meta, RuleEdit{Permit: &permit, By: f.panel, Exact: true, TTL: MetaRuleLapse, Why: "Let opencode answer OpenAbstractions questions for you"}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("the enrollment %+v %v", edit, err)
	}
	read := f.p.ReadRule(f.holder, MetaAnswerAction, MetaScopeApps)
	expires, err := time.Parse(time.RFC3339Nano, read.Record.Expires)
	if err != nil || !expires.Equal(f.now.Add(MetaRuleLapse)) {
		t.Fatalf("the enrollment lapse %q %v", read.Record.Expires, err)
	}
	if yes, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || !yes {
		t.Fatalf("no completion proof %v %v", yes, err)
	}
}
