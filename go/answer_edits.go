package rights

import (
	"encoding/json"
	"errors"
	"slices"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// StopAnswerer withdraws future answering authority. Cleanup is an explicit
// optional part of the same rights edit and concerns current permits by this
// answerer across all of its enrollments. Existing denies and other setters
// are untouched. The policy revision and operator authority are checked while
// the state lock is held.
func (p *DecisionPolicy) StopAnswerer(expected string, answerer wire.Subject, alsoRevokeGrants bool, authorize func() error) (wire.PolicyEdit, error) {
	answerer, err := NormalizeDecisionSubject(answerer)
	if err != nil || !boundedDecisionString(expected, 128) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if authorize == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err := p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: stop without write")
	err = p.change(func(data []byte) ([]byte, error) {
		result = wire.PolicyEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if p.revision(f) != expected {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: p.revision(f)}
			return nil, noWrite
		}
		key := keyOnce()
		before := len(f.Rules)
		f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool {
			if IsMetaRule(r.Action, r.Resource) && sameTarget(r, answerer, MetaAnswerAction, MetaScopeApps, key) {
				return true
			}
			return alsoRevokeGrants && r.Permit && !IsMetaRule(r.Action, r.Resource) && setByHolder(r, answerer, key)
		})
		if len(f.Rules) == 0 {
			f.Rules = nil
		}
		if len(f.Rules) == before {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: p.revision(f)}
			return nil, noWrite
		}
		f.Profile = DecisionProfile
		result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: p.revision(f)}
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

// RevokeAnswerPermits removes the still-current effects of a retained answer.
// A paired action left by an older answer, or changed later, stays untouched.
// The private ID distinguishes same-millisecond replacements even when an
// older content-hash revision is recreated. Old grants without an ID cannot
// be selected by this operation.
func (p *DecisionPolicy) RevokeAnswerPermits(expected string, answerer, target wire.Subject, actions []string, resource, questionID string, authorize func() error) (wire.PolicyEdit, error) {
	answerer, ae := NormalizeDecisionSubject(answerer)
	target, te := NormalizeDecisionSubject(target)
	if ae != nil || te != nil || !boundedDecisionString(expected, 128) || !boundedDecisionString(questionID, 128) ||
		len(actions) < 1 || len(actions) > 2 || !boundedDecisionString(resource, 1024) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	for i, action := range actions {
		if !ValidDecisionQuery(action, resource) || IsMetaRule(action, resource) || slices.Contains(actions[:i], action) {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
		}
	}
	if authorize == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err := p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: answer revoke without write")
	err := p.change(func(data []byte) ([]byte, error) {
		result = wire.PolicyEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		currentRevision := p.revision(f)
		if currentRevision != expected {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: currentRevision}
			return nil, noWrite
		}
		key := keyOnce()
		now := p.now()
		indices := make([]int, 0, len(actions))
		for _, action := range actions {
			index := -1
			seen := false
			for i, r := range f.Rules {
				if sameTarget(r, target, action, resource, key) {
					if seen {
						result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: currentRevision}
						return nil, noWrite
					}
					seen = true
					if r.Permit && !expired(r, now) && r.QuestionID == questionID && setByHolder(r, answerer, key) {
						index = i
					}
				}
			}
			if index >= 0 {
				indices = append(indices, index)
			}
		}
		if len(indices) == 0 {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: currentRevision}
			return nil, noWrite
		}
		slices.Sort(indices)
		for i := len(indices) - 1; i >= 0; i-- {
			f.Rules = slices.Delete(f.Rules, indices[i], indices[i]+1)
		}
		if len(f.Rules) == 0 {
			f.Rules = nil
		}
		f.Profile = DecisionProfile
		result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: p.revision(f)}
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
