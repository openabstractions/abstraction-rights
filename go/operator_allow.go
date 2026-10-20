package rights

import (
	"context"
	"slices"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// MaxAppliedOperatorAnswers is the runtime Book's maximum retained occurrences.
const MaxAppliedOperatorAnswers = 4096

func validAnswerID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type operatorAllowReceipt struct {
	id       string
	retained []string
}

// ApplyFirstUseAllow commits complete derived permits and their occurrence's
// success proof together. The trusted host pins the authoritative Book while
// calling it and supplies every retained ID. Ordinary setters create no proof.
// A completed ID conflicts without rewriting rights, including after revocation.
//
// An enrollment asked at first use (RIGHTS-R16) is the one exception to a
// permanent permit: its single meta-rule carries exactly MetaRuleLapse, as
// the operator UI writes it, and no question identity, so an answerer's
// Undo can never reach it. Its completion proof is recorded as for any
// other allow.
func (p *DecisionPolicy) ApplyFirstUseAllow(ctx context.Context, expected string, rules []wire.PolicyRule, edit RuleEdit, id string, retained []string, authorize func() error) (wire.PolicyEdit, error) {
	meta := len(rules) == 1 && IsMetaRule(rules[0].Action, rules[0].Resource)
	if !validAnswerID(id) || len(retained) > MaxAppliedOperatorAnswers || !slices.Contains(retained, id) || edit.Permit == nil || !*edit.Permit || edit.PreserveOtherSetter ||
		!(edit.TTL == 0 && !meta || meta && edit.TTL == MetaRuleLapse) || !edit.Deadline.IsZero() {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	retained = slices.Clone(retained)
	slices.Sort(retained)
	for i, value := range retained {
		if !validAnswerID(value) || i > 0 && retained[i-1] == value {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
		}
	}
	if !meta {
		edit.QuestionID = id
	}
	return p.changeRules(ctx, expected, rules, edit, authorize, &operatorAllowReceipt{id, retained})
}

// AppliedFirstUseAllow reads durable completion, independently of whether its
// current permits still exist. It supplies no authority to an application.
func (p *DecisionPolicy) AppliedFirstUseAllow(id string) (bool, error) {
	f, _, err := p.readDecision()
	return slices.Contains(f.AppliedOperatorAnswers, id), err
}
