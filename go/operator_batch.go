package rights

import (
	"context"
	"encoding/json"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	"slices"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// ErrRuleDeadline means the delegated authority cannot cover even one more
// millisecond at the rights edit time.
var ErrRuleDeadline = errors.New("rights: delegated permission deadline passed")

// ChangeRules writes one or two same-target, same-permit rules in a single
// conditional rights edit. The operator's explicit edit may replace opposite
// rules; a delegated caller sets PreserveOtherSetter to protect the person's
// current rule. Every precondition is checked before either member mutates.
func (p *DecisionPolicy) ChangeRules(expected string, rules []wire.PolicyRule, edit RuleEdit, authorize func() error) (wire.PolicyEdit, error) {
	return p.changeRules(context.Background(), expected, rules, edit, authorize, nil)
}

func (p *DecisionPolicy) changeRules(ctx context.Context, expected string, rules []wire.PolicyRule, edit RuleEdit, authorize func() error, receipt *operatorAllowReceipt) (wire.PolicyEdit, error) {
	if len(rules) < 1 || len(rules) > 2 || edit.Permit == nil || !boundedDecisionString(expected, 128) ||
		edit.TTL < 0 || edit.TTL > MaxRuleTTL || edit.TTL%time.Millisecond != 0 || !validWhy(edit.Why) ||
		(edit.QuestionID != "" && (!boundedDecisionString(edit.QuestionID, 128) || !*edit.Permit)) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	by, err := NormalizeDecisionSubject(edit.By)
	if err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	base, err := writableSubject(rules[0].Subject)
	if errors.Is(err, ErrUnresolvedShortName) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, err
	}
	if err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	for i := range rules {
		s, e := writableSubject(rules[i].Subject)
		if errors.Is(e, ErrUnresolvedShortName) {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, e
		}
		if e != nil || s.Account != base.Account || !identity.SameSubjectProgram(s.Program, base.Program) || rules[i].Resource != rules[0].Resource || rules[i].Permit != *edit.Permit ||
			!ValidDecisionQuery(rules[i].Action, rules[i].Resource) || (edit.QuestionID != "" && IsMetaRule(rules[i].Action, rules[i].Resource)) || validMetaEdit(rules[i].Action, rules[i].Resource, edit.Permit, edit.TTL) != nil ||
			p.refuseHolder(s, rules[i].Action, rules[i].Resource, edit.Permit) != nil {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
		}
		for j := 0; j < i; j++ {
			if rules[j].Action == rules[i].Action {
				return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
			}
		}
		rules[i].Subject = s
	}
	if authorize == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err := p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: grouped edit without write")
	change := p.change
	if receipt != nil {
		change = func(edit func([]byte) ([]byte, error)) error { return p.changeContext(ctx, edit) }
	}
	err = change(func(data []byte) ([]byte, error) {
		result = wire.PolicyEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		catalogue := p.catalogue(f)
		for _, rule := range rules {
			if !slices.Contains(catalogue, rule.Action) {
				result.Outcome = wire.PolicyEditOutcomeInvalid
				return nil, noWrite
			}
		}
		if p.revision(f) != expected || receipt != nil && slices.Contains(f.AppliedOperatorAnswers, receipt.id) {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: p.revision(f)}
			if current, found := decidingRule(f.Rules, base, rules[0].Action, rules[0].Resource, p.now(), keyOnce()); found {
				public := publicRule(current)
				result.Current = &public
			}
			return nil, noWrite
		}
		now := p.now()
		ttl := edit.TTL
		if !edit.Deadline.IsZero() {
			if !now.Before(edit.Deadline) {
				return nil, ErrRuleDeadline
			}
			cap := edit.Deadline.Sub(now).Truncate(time.Millisecond) - time.Millisecond
			if cap < time.Millisecond {
				return nil, ErrRuleDeadline
			}
			if ttl == 0 || ttl > cap {
				ttl = cap
			}
		}
		skip := make([]bool, len(rules))
		if edit.PreserveOtherSetter {
			key := keyOnce()
			for i, rule := range rules {
				if current, found := decidingRule(f.Rules, base, rule.Action, rule.Resource, now, key); found && !expired(current, now) {
					if !current.Permit {
						public := publicRule(current)
						result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: p.revision(f), Current: &public}
						return nil, noWrite
					}
					if !setByHolder(current, by, key) {
						skip[i] = true
					}
				}
			}
		}
		changedAny := false
		for i, rule := range rules {
			if skip[i] {
				continue
			}
			permit := rule.Permit
			changed, err := applyDecisionRule(&f, rule.Subject, rule.Action, rule.Resource,
				ruleChange{permit: &permit, by: by, at: now, ttl: ttl, why: edit.Why, exact: edit.Exact, questionID: edit.QuestionID})
			if err != nil {
				return nil, err
			}
			changedAny = changedAny || changed
		}
		if receipt != nil {
			f.AppliedOperatorAnswers = slices.DeleteFunc(f.AppliedOperatorAnswers, func(id string) bool {
				_, retained := slices.BinarySearch(receipt.retained, id)
				return !retained
			})
			f.AppliedOperatorAnswers = append(f.AppliedOperatorAnswers, receipt.id)
			slices.Sort(f.AppliedOperatorAnswers)
			changedAny = true
		}
		if changedAny {
			f.Profile = DecisionProfile
		}
		result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: p.revision(f)}
		if current, found := decidingRule(f.Rules, base, rules[0].Action, rules[0].Resource, now, keyOnce()); found {
			public := publicRule(current)
			result.Current = &public
		}
		if !changedAny {
			return nil, noWrite
		}
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	return result, nil
}
