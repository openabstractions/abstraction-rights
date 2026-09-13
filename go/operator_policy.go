package rights

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	cas "github.com/openabstractions/abstraction-cas/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"slices"
)

// PolicySnapshot is a bounded native view for an explicitly authorized service.
type PolicySnapshot struct {
	Revision string
	Catalog  []string
	Rules    []wire.PolicyRule
}

func decisionRevision(f decisionFile) string {
	data, _ := json.Marshal(f)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func publicRule(r decisionRule) wire.PolicyRule {
	return wire.PolicyRule{Subject: r.Subject, Action: r.Action, Resource: r.Resource, Permit: r.Permit}
}
func (p *DecisionPolicy) OperatorSnapshot() (PolicySnapshot, error) {
	f, revision, err := p.readDecision()
	if err != nil {
		return PolicySnapshot{}, err
	}
	result := PolicySnapshot{Revision: revision, Catalog: slices.Clone(f.Catalog), Rules: []wire.PolicyRule{}}
	for _, r := range f.Rules {
		result.Rules = append(result.Rules, publicRule(r))
	}
	return result, nil
}

// EditRule compares the expected revision and rechecks trusted authorization
// inside the existing CAS edit. A stale revision always conflicts. Native
// Set/Revoke remain explicit unconditional operator APIs.
func (p *DecisionPolicy) EditRule(expected string, subject wire.Subject, action, resource string, permit *bool, authorize func() error) (wire.PolicyEdit, error) {
	subject, err := NormalizeDecisionSubject(subject)
	if err != nil || !ValidDecisionQuery(action, resource) || !boundedDecisionString(expected, 128) || !slices.Contains(p.catalog, action) {
		return wire.PolicyEdit{Outcome: "invalid"}, nil
	}
	if authorize == nil {
		return wire.PolicyEdit{Outcome: "unavailable"}, errors.New("rights: operator admission required")
	}
	if err = p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: "unavailable"}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: policy edit without write")
	key := ruleKey(decisionRule{Subject: subject, Action: action, Resource: resource})
	capture := func(f decisionFile) {
		result.Revision = decisionRevision(f)
		for _, r := range f.Rules {
			if ruleKey(r) == key {
				current := publicRule(r)
				result.Current = &current
				break
			}
		}
	}
	err = cas.ChangeLimit(p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) {
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if decisionRevision(f) != expected {
			result.Outcome = "conflict"
			capture(f)
			return nil, noWrite
		}
		changed, err := applyDecisionRule(&f, subject, action, resource, permit)
		if err != nil {
			return nil, err
		}
		result.Outcome = "applied"
		capture(f)
		if !changed {
			return nil, noWrite
		}
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if err != nil {
		return wire.PolicyEdit{Outcome: "unavailable"}, err
	}
	return result, nil
}
