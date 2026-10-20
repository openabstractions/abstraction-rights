package rights

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// A meta-rule is a rule over other rules (research/rights-model/PROPOSAL.md
// §6): a permit for a meta-permission on a class scope. This file owns the
// one the 0.4.0 slice defines, answering every app's routine questions
// (RIGHTS-R16, asks ASK-R5), and renewal of permits that shared its expiry.
const (
	// MetaAnswerAction is asks' answer permission (asks ASK-R1, ASK-R5).
	MetaAnswerAction = "abstraction.asks/question.answer"
	// MetaScopeApps is the class scope "every app, including later ones".
	MetaScopeApps = "apps"
	// MetaRuleLapse is how long a class-scoped meta-rule lasts without use.
	// Each use moves its expiry to this long after the use (RIGHTS-R16).
	MetaRuleLapse = 30 * 24 * time.Hour
)

var (
	// ErrMetaRuleExpiry refuses a class-scoped meta permit with no expiry or
	// one beyond MetaRuleLapse.
	ErrMetaRuleExpiry = errors.New("rights: a class-scoped meta-rule permit expires within its lapse")
	// ErrNoMetaRule refuses a holder's write when its meta-rule is absent,
	// expired or a deny at the moment of the edit.
	ErrNoMetaRule = errors.New("rights: the holder holds no current meta-rule")
	// ErrMetaTarget refuses a holder's write on a meta-permission or on a rule
	// whose subject is the holder itself.
	ErrMetaTarget = errors.New("rights: a holder writes no meta-rule and no rule about itself")
)

// ErrMetaHolder refuses a meta-rule permit for the service's own program or
// one the host's MetaHolder refuses.
var ErrMetaHolder = errors.New("rights: this program cannot hold a class-scoped meta-rule")

// refuseHolder refuses writing a class-scoped meta permit for the service's
// own program, or for one the host's MetaHolder refuses: optional Stop
// cleanup takes permits the holder set, and those programs set the person's
// own rules.
func (p *DecisionPolicy) refuseHolder(subject wire.Subject, action, resource string, permit *bool) error {
	if permit == nil || !*permit || !IsMetaRule(action, resource) {
		return nil
	}
	if subject.Account == p.native.Account && identity.SameSubjectProgram(subject.Program, p.native.Program) {
		return ErrMetaHolder
	}
	if p.MetaHolder != nil {
		if err := p.MetaHolder(subject); err != nil {
			return fmt.Errorf("%w: %v", ErrMetaHolder, err)
		}
	}
	return nil
}

// IsMetaRule reports whether action and resource name a class-scoped
// meta-rule.
func IsMetaRule(action, resource string) bool {
	return action == MetaAnswerAction && resource == MetaScopeApps
}

// setByHolder reports whether the holder set r: the same account and, by the
// shared program identity rules, the same program.
func setByHolder(r decisionRule, holder wire.Subject, key programKeys) bool {
	return r.SetBy.Account == holder.Account &&
		identity.SameNormalizedSubjectProgramKeyed(r.SetBy.Program, holder.Program,
			func() string { return key(r.SetBy.Program) }, func() string { return key(holder.Program) })
}

// liveMeta is the holder's meta-rule in force at now: an unexpired permit.
func liveMeta(rules []decisionRule, holder wire.Subject, now time.Time, key programKeys) (decisionRule, bool) {
	r, found := decidingRule(rules, holder, MetaAnswerAction, MetaScopeApps, now, key)
	if !found || !r.Permit || expired(r, now) {
		return decisionRule{}, false
	}
	return r, true
}

// cascadeMeta carries grants with a renewed enrollment expiry. Withdrawing
// enrollment leaves existing grants at their stamped expiry; StopAnswerer
// performs optional cleanup explicitly in the same policy edit.
func cascadeMeta(f *decisionFile, old decisionRule, next *decisionRule, key programKeys) {
	holder := old.Subject
	if next == nil || !next.Permit {
		return
	}
	if next.Expires == old.Expires || old.Expires == "" {
		return
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.Permit && r.Expires == old.Expires && !IsMetaRule(r.Action, r.Resource) && setByHolder(*r, holder, key) {
			r.Expires = next.Expires
		}
	}
}

// validMetaEdit refuses a class-scoped meta permit with no expiry or one
// beyond MetaRuleLapse.
func validMetaEdit(action, resource string, permit *bool, ttl time.Duration) error {
	if permit != nil && *permit && IsMetaRule(action, resource) && (ttl <= 0 || ttl > MetaRuleLapse) {
		return ErrMetaRuleExpiry
	}
	return nil
}

// ChangeRuleUnder is one write a meta-rule's holder makes for the person
// (RIGHTS-R16). In one atomic edit it reads the holder's meta-rule, refusing
// with ErrNoMetaRule unless it is an unexpired permit; renews it to
// MetaRuleLapse after the edit time, taking along the permits that expired
// with it; and, when permit is set, writes the exact permit on target, set
// by holder and expiring with the meta-rule. A nil permit renews only.
//
// A holder never writes a meta-permission or a rule about itself
// (ErrMetaTarget). A target rule in force that someone else set stays: a
// deny conflicts, and a permit makes the write a no-op that still renews.
// authorize runs inside the edit, after lock waiting, before anything is
// read.
func (p *DecisionPolicy) ChangeRuleUnder(holder, target wire.Subject, action, resource string, permit bool, why string, authorize func() error) (wire.PolicyEdit, error) {
	return p.ChangeRuleUnderAnswer(holder, target, action, resource, permit, why, "", authorize)
}

// ChangeRuleUnderAnswer records the trusted asks question ID on a newly
// written permit. An unchanged permit keeps its original effect identity.
func (p *DecisionPolicy) ChangeRuleUnderAnswer(holder, target wire.Subject, action, resource string, permit bool, why, questionID string, authorize func() error) (wire.PolicyEdit, error) {
	if !permit {
		return p.ChangeRulesUnderAnswer(holder, target, nil, resource, why, questionID, authorize)
	}
	return p.ChangeRulesUnderAnswer(holder, target, []string{action}, resource, why, questionID, authorize)
}

// ChangeRulesUnderAnswer writes a first-use answer's one or two related
// permits in one policy edit. A conflict on either target writes neither.
// An empty actions list only renews the enrollment for a refusal.
func (p *DecisionPolicy) ChangeRulesUnderAnswer(holder, target wire.Subject, actions []string, resource, why, questionID string, authorize func() error) (wire.PolicyEdit, error) {
	if len(actions) > 2 || (questionID != "" && !boundedDecisionString(questionID, 128)) || (len(actions) == 0 && questionID != "") {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	holder, err := NormalizeDecisionSubject(holder)
	if err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if len(actions) > 0 {
		if target, err = writableSubject(target); err != nil {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
		}
		if target.Account == holder.Account && identity.SameSubjectProgram(target.Program, holder.Program) {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeForbidden}, ErrMetaTarget
		}
		for i, action := range actions {
			if !ValidDecisionQuery(action, resource) || slices.Contains(actions[:i], action) {
				return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
			}
			if action == MetaAnswerAction {
				return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeForbidden}, ErrMetaTarget
			}
		}
	}
	if !validWhy(why) || authorize == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if err = p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: holder edit without write")
	err = p.change(func(data []byte) ([]byte, error) {
		result = wire.PolicyEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		catalogue := p.catalogue(f)
		if !slices.Contains(catalogue, MetaAnswerAction) {
			result.Outcome = wire.PolicyEditOutcomeInvalid
			return nil, noWrite
		}
		for _, action := range actions {
			if !slices.Contains(catalogue, action) {
				result.Outcome = wire.PolicyEditOutcomeInvalid
				return nil, noWrite
			}
		}
		now := p.now()
		key := keyOnce()
		meta, live := liveMeta(f.Rules, holder, now, key)
		if !live {
			result.Outcome = wire.PolicyEditOutcomeForbidden
			return nil, ErrNoMetaRule
		}
		skip := make([]bool, len(actions))
		for i, action := range actions {
			if current, found := decidingRule(f.Rules, target, action, resource, now, key); found && !expired(current, now) {
				result.Revision = p.revision(f)
				public := publicRule(current)
				result.Current = &public
				if !current.Permit {
					result.Outcome = wire.PolicyEditOutcomeConflict
					return nil, noWrite
				}
				if !setByHolder(current, holder, key) {
					skip[i] = true
				} // the person's own permit stands
			}
		}
		renewed := meta
		renewed.Expires = stamp(now.Add(MetaRuleLapse))
		for i := range f.Rules {
			if sameTarget(f.Rules[i], holder, MetaAnswerAction, MetaScopeApps, key) && f.Rules[i].Permit && !expired(f.Rules[i], now) {
				f.Rules[i].Expires = renewed.Expires
			}
		}
		cascadeMeta(&f, meta, &renewed, key)
		for i, action := range actions {
			if skip[i] {
				continue
			}
			permit := true
			if _, err := applyDecisionRule(&f, target, action, resource, ruleChange{permit: &permit, by: holder, at: now, ttl: MetaRuleLapse, why: why, exact: true, questionID: questionID}); err != nil {
				return nil, err
			}
		}
		f.Profile = DecisionProfile
		result.Outcome = wire.PolicyEditOutcomeApplied
		result.Revision = p.revision(f)
		if len(actions) == 0 {
			return json.Marshal(f)
		}
		if r, found := decidingRule(f.Rules, target, actions[0], resource, now, key); found {
			public := publicRule(r)
			result.Current = &public
		}
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if errors.Is(err, ErrNoMetaRule) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeForbidden}, err
	}
	if err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	return result, nil
}
