package rights

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func pairingRules(t *testing.T, p *DecisionPolicy, account string) []wire.PolicyRule {
	t.Helper()
	subject := wire.Subject{Account: account, Program: "remote:" + strings.Repeat("a", 64)}
	rules := []wire.PolicyRule{
		{Subject: subject, Action: "example.remote/serve", Resource: "account:receiver", Permit: true},
		{Subject: subject, Action: "example.router/read", Resource: "inventory:receiver", Permit: true},
		{Subject: subject, Action: "example.inference/complete", Resource: "host:chosen", Permit: true},
	}
	for _, r := range rules {
		if err := p.RegisterAction(r.Action); err != nil {
			t.Fatal(err)
		}
	}
	return rules
}

func TestRemotePairingAtomicProofAndRevocation(t *testing.T) {
	f := newMetaFixture(t)
	rules := pairingRules(t, f.p, f.panel.Account)
	yes := true
	edit := RuleEdit{Permit: &yes, By: f.panel}
	before := f.revision(t)
	for _, count := range []int{2, 3} {
		old, err := f.p.ChangeRules(before, rules[:count], edit, func() error { return nil })
		if err != nil || old.Outcome != wire.PolicyEditOutcomeInvalid || f.revision(t) != before {
			t.Fatalf("old batch boundary: %+v %v", old, err)
		}
		old, err = f.p.ApplyFirstUseAllow(context.Background(), before, rules[:count], edit, operatorQ1, []string{operatorQ1}, func() error { return nil })
		if err != nil || old.Outcome != wire.PolicyEditOutcomeInvalid || f.revision(t) != before {
			t.Fatalf("old first-use boundary: %+v %v", old, err)
		}
	}
	result, err := f.p.ApplyRemotePairingAllowContext(context.Background(), before, rules, edit, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || result.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("complete effect: %+v %v", result, err)
	}
	for _, r := range rules {
		if f.p.Decide(r.Subject, r.Action, r.Resource).Outcome != wire.DecisionOutcomePermitted {
			t.Fatalf("missing member: %+v", r)
		}
	}
	if err := f.p.Revoke(rules[1].Subject, rules[1].Action, rules[1].Resource); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadDecisionPolicy(f.p.path, f.p.seed)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := restarted.AppliedFirstUseAllow(operatorQ1); err != nil || !ok {
		t.Fatalf("lost reply proof: %v %v", ok, err)
	}
	snapshot, _ := restarted.OperatorSnapshot()
	result, err = restarted.ApplyRemotePairingAllowContext(context.Background(), snapshot.Revision, rules, edit, operatorQ1, []string{operatorQ1}, func() error { return nil })
	if err != nil || result.Outcome != wire.PolicyEditOutcomeConflict || restarted.Decide(rules[1].Subject, rules[1].Action, rules[1].Resource).Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("replay restored revoked member: %+v %v", result, err)
	}
}

func TestRemotePairingBlocksRefuseWholeEffect(t *testing.T) {
	for blocked := 0; blocked < 3; blocked++ {
		t.Run(string(rune('a'+blocked)), func(t *testing.T) {
			f := newMetaFixture(t)
			rules := pairingRules(t, f.p, f.panel.Account)
			yes, no := true, false
			r := rules[blocked]
			result, err := f.p.ChangeRule(f.revision(t), r.Subject, r.Action, r.Resource, RuleEdit{Permit: &no, By: f.panel, Exact: true}, func() error { return nil })
			if err != nil || result.Outcome != wire.PolicyEditOutcomeApplied {
				t.Fatalf("block: %+v %v", result, err)
			}
			before, _ := os.ReadFile(f.p.path)
			result, err = f.p.ApplyRemotePairingAllowContext(context.Background(), f.revision(t), rules, RuleEdit{Permit: &yes, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { return nil })
			after, _ := os.ReadFile(f.p.path)
			if err != nil || result.Outcome != wire.PolicyEditOutcomeConflict || !bytes.Equal(before, after) {
				t.Fatalf("partial effect or overwritten block: %+v %v", result, err)
			}
		})
	}
}

func TestRemotePairingPreservesAnotherNativeSetter(t *testing.T) {
	f := newMetaFixture(t)
	rules := pairingRules(t, f.p, f.panel.Account)
	yes := true
	r := rules[1]
	prior, err := f.p.ChangeRule(f.revision(t), r.Subject, r.Action, r.Resource, RuleEdit{Permit: &yes, By: f.holder, Exact: true, Why: "existing native approval"}, func() error { return nil })
	if err != nil || prior.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("prior permit: %+v %v", prior, err)
	}
	before := f.p.ReadRule(r.Subject, r.Action, r.Resource)
	result, err := f.p.ApplyRemotePairingAllowContext(context.Background(), f.revision(t), rules, RuleEdit{Permit: &yes, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { return nil })
	after := f.p.ReadRule(r.Subject, r.Action, r.Resource)
	if err != nil || result.Outcome != wire.PolicyEditOutcomeApplied || !reflect.DeepEqual(before.Record, after.Record) {
		t.Fatalf("other setter replaced: before=%+v after=%+v result=%+v %v", before, after, result, err)
	}
	if ok, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || !ok {
		t.Fatalf("complete receipt: %v %v", ok, err)
	}
}

func TestRemotePairingAdmissionAndCommitRefusals(t *testing.T) {
	for _, mode := range []string{"stale", "native", "cancel", "moved"} {
		t.Run(mode, func(t *testing.T) {
			f := newMetaFixture(t)
			rules := pairingRules(t, f.p, f.panel.Account)
			yes := true
			before := f.revision(t)
			original, _ := os.ReadFile(f.p.path)
			competing := original
			if mode == "moved" {
				other := newMetaFixture(t)
				pairingRules(t, other.p, f.panel.Account)
				if err := other.p.Set(rules[0].Subject, decisionAction, "concurrent", true); err != nil {
					t.Fatal(err)
				}
				competing, _ = os.ReadFile(other.p.path)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expected := before
			if mode == "stale" {
				expected = "stale"
			}
			runs := 0
			authorize := func() error {
				runs++
				if mode == "native" || mode == "moved" && runs == 2 {
					return errors.New("current native approval withdrawn")
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "moved" && runs == 1 {
					return os.WriteFile(f.p.path, competing, 0600)
				}
				return nil
			}
			result, err := f.p.ApplyRemotePairingAllowContext(ctx, expected, rules, RuleEdit{Permit: &yes, By: f.panel}, operatorQ1, []string{operatorQ1}, authorize)
			after, _ := os.ReadFile(f.p.path)
			want := original
			if mode == "moved" {
				want = competing
				if runs != 2 {
					t.Fatalf("authorization retry count %d", runs)
				}
			}
			if result.Outcome == wire.PolicyEditOutcomeApplied || !bytes.Equal(after, want) {
				t.Fatalf("failed commit wrote effect: %+v %v", result, err)
			}
			if ok, e := f.p.AppliedFirstUseAllow(operatorQ1); e != nil || ok {
				t.Fatalf("failed receipt: %v %v", ok, e)
			}
		})
	}
}

func TestRemotePairingValidationAndSnapshot(t *testing.T) {
	for _, mode := range []string{"empty", "native-subject", "foreign-account", "remote-actor", "false", "duplicate", "unregistered", "meta", "overflow", "ttl", "deadline", "receipt", "nil-authorize"} {
		t.Run(mode, func(t *testing.T) {
			f := newMetaFixture(t)
			rules := pairingRules(t, f.p, f.panel.Account)
			yes := true
			edit := RuleEdit{Permit: &yes, By: f.panel}
			id := operatorQ1
			authorize := func() error { return nil }
			switch mode {
			case "empty":
				rules = nil
			case "native-subject":
				for i := range rules {
					rules[i].Subject = f.appA
				}
			case "foreign-account":
				edit.By.Account = "other-account"
			case "remote-actor":
				edit.By = rules[0].Subject
			case "false":
				rules[1].Permit = false
			case "duplicate":
				rules[1].Action = rules[0].Action
				rules[1].Resource = rules[0].Resource
			case "unregistered":
				rules[1].Action = "example/unknown"
			case "meta":
				rules[1].Action, rules[1].Resource = MetaAnswerAction, MetaScopeApps
			case "overflow":
				for len(rules) <= MaxPermissionEffect {
					rules = append(rules, rules[0])
				}
			case "ttl":
				edit.TTL = time.Millisecond
			case "deadline":
				edit.Deadline = time.Now().Add(time.Hour)
			case "receipt":
				id = "bad"
			case "nil-authorize":
				authorize = nil
			}
			before, _ := os.ReadFile(f.p.path)
			result, err := f.p.ApplyRemotePairingAllowContext(context.Background(), f.revision(t), rules, edit, id, []string{id}, authorize)
			after, _ := os.ReadFile(f.p.path)
			if result.Outcome == wire.PolicyEditOutcomeApplied || !bytes.Equal(before, after) {
				t.Fatalf("invalid effect wrote: %+v %v", result, err)
			}
		})
	}
	f := newMetaFixture(t)
	rules := pairingRules(t, f.p, f.panel.Account)
	original := rules[0]
	yes := true
	result, err := f.p.ApplyRemotePairingAllowContext(context.Background(), f.revision(t), rules, RuleEdit{Permit: &yes, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { rules[0].Resource = "mutated"; yes = false; return nil })
	if err != nil || result.Outcome != wire.PolicyEditOutcomeApplied || f.p.Decide(original.Subject, original.Action, original.Resource).Outcome != wire.DecisionOutcomePermitted {
		t.Fatalf("caller mutation changed validated effect: %+v %v", result, err)
	}
}

func TestRemotePairingSameActionDistinctResources(t *testing.T) {
	for _, blocked := range []int{-1, 0, 1} {
		t.Run(string(rune('b'+blocked)), func(t *testing.T) {
			f := newMetaFixture(t)
			rules := pairingRules(t, f.p, f.panel.Account)[:2]
			rules[1].Action = rules[0].Action
			yes, no := true, false
			if blocked >= 0 {
				r := rules[blocked]
				result, err := f.p.ChangeRule(f.revision(t), r.Subject, r.Action, r.Resource, RuleEdit{Permit: &no, By: f.panel, Exact: true}, func() error { return nil })
				if err != nil || result.Outcome != wire.PolicyEditOutcomeApplied {
					t.Fatalf("block setup: %+v %v", result, err)
				}
			}
			before, _ := os.ReadFile(f.p.path)
			result, err := f.p.ApplyRemotePairingAllowContext(context.Background(), f.revision(t), rules, RuleEdit{Permit: &yes, By: f.panel}, operatorQ1, []string{operatorQ1}, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if blocked >= 0 {
				after, _ := os.ReadFile(f.p.path)
				if result.Outcome != wire.PolicyEditOutcomeConflict || !bytes.Equal(before, after) {
					t.Fatalf("partial effect: %+v", result)
				}
				if ok, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || ok {
					t.Fatalf("blocked receipt: %v %v", ok, err)
				}
				return
			}
			if result.Outcome != wire.PolicyEditOutcomeApplied {
				t.Fatalf("distinct exact resources: %+v", result)
			}
			for _, r := range rules {
				if f.p.Decide(r.Subject, r.Action, r.Resource).Outcome != wire.DecisionOutcomePermitted {
					t.Fatalf("missing member: %+v", r)
				}
			}
			if ok, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || !ok {
				t.Fatalf("complete receipt: %v %v", ok, err)
			}
		})
	}
}
