package rights

import (
	"slices"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestProviderFirstUseDoesNotWidenOrdinaryOrMalformedGroupedEdits(t *testing.T) {
	for _, variant := range []string{"ordinary", "different-name", "different-subject", "different-account", "reversed"} {
		t.Run(variant, func(t *testing.T) {
			f := newMetaFixture(t)
			rules := []wire.PolicyRule{{Subject: f.appA, Action: "abstraction.credentials/apply", Resource: "credential:deepseek", Permit: true}, {Subject: f.appA, Action: "abstraction.inference/complete", Resource: "host:deepseek", Permit: true}}
			for _, rule := range rules {
				if err := f.p.RegisterAction(rule.Action); err != nil {
					t.Fatal(err)
				}
			}
			switch variant {
			case "different-name":
				rules[1].Resource = "host:other"
			case "different-subject":
				rules[1].Subject = f.appB
			case "different-account":
				rules[1].Subject.Account = "other-account"
			case "reversed":
				slices.Reverse(rules)
			}
			before := f.revision(t)
			yes := true
			edit := RuleEdit{Permit: &yes, By: f.panel, Exact: true}
			var result wire.PolicyEdit
			var err error
			if variant == "ordinary" {
				result, err = f.p.ChangeRules(before, rules, edit, func() error { return nil })
			} else {
				result, err = f.p.ApplyFirstUseAllow(t.Context(), before, rules, edit, operatorQ1, []string{operatorQ1}, func() error { return nil })
			}
			if err != nil || result.Outcome != wire.PolicyEditOutcomeInvalid || f.revision(t) != before {
				t.Fatal(result, err)
			}
			if applied, err := f.p.AppliedFirstUseAllow(operatorQ1); err != nil || applied {
				t.Fatal("invalid pair wrote receipt", applied, err)
			}
		})
	}
}
