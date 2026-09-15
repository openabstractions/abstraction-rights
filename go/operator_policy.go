package rights

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	cas "github.com/openabstractions/abstraction-cas/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"slices"
	"time"
)

// PolicySnapshot is a bounded native view for an explicitly authorized service.
// Rules are every retained rule, including expired rules the next write removes.
type PolicySnapshot struct {
	Revision string
	Catalog  []string
	Rules    []wire.PolicyRule
}

// revision identifies the configured seed together with the file content, so a
// changed seed changes the revision as a changed file does.
func (p *DecisionPolicy) revision(f decisionFile) string {
	data, _ := json.Marshal(struct {
		Seed []string     `json:"seed"`
		File decisionFile `json:"file"`
	}{p.seed, f})
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
	result := PolicySnapshot{Revision: revision, Catalog: p.catalogue(f), Rules: []wire.PolicyRule{}}
	for _, r := range f.Rules {
		result.Rules = append(result.Rules, publicRule(r))
	}
	return result, nil
}

// RuleEdit is one conditional edit of an exact rule. A nil Permit revokes. By is
// the subject the receiving service established for the editing party. Exact
// compares Why and the resulting expiry as well as Permit when deciding whether
// the edit is a no-op; SetRule leaves it false.
type RuleEdit struct {
	Permit *bool
	By     wire.Subject
	TTL    time.Duration
	Why    string
	Exact  bool
}

// EditRule compares the expected revision and rechecks trusted authorization
// inside the existing CAS edit, recording the service's own subject. Native
// Set/Revoke remain explicit unconditional operator APIs.
func (p *DecisionPolicy) EditRule(expected string, subject wire.Subject, action, resource string, permit *bool, authorize func() error) (wire.PolicyEdit, error) {
	return p.ChangeRule(expected, subject, action, resource, RuleEdit{Permit: permit, By: p.native}, authorize)
}

// ChangeRule is EditRule with provenance, reason and expiry. A stale revision
// always conflicts. An uncatalogued action or an out-of-bounds edit is invalid.
func (p *DecisionPolicy) ChangeRule(expected string, subject wire.Subject, action, resource string, edit RuleEdit, authorize func() error) (wire.PolicyEdit, error) {
	subject, err := NormalizeDecisionSubject(subject)
	by, byErr := NormalizeDecisionSubject(edit.By)
	if err != nil || byErr != nil || !ValidDecisionQuery(action, resource) || !boundedDecisionString(expected, 128) ||
		edit.TTL < 0 || edit.TTL > MaxRuleTTL || edit.TTL%time.Millisecond != 0 || !validWhy(edit.Why) || (edit.Permit == nil && (edit.TTL != 0 || edit.Why != "")) {
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
		result.Revision = p.revision(f)
		for _, r := range f.Rules {
			if ruleKey(r) == key {
				current := publicRule(r)
				result.Current = &current
				break
			}
		}
	}
	change := ruleChange{permit: edit.Permit, by: by, at: p.now(), ttl: edit.TTL, why: edit.Why, exact: edit.Exact}
	err = cas.ChangeLimit(p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) {
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(p.catalogue(f), action) {
			result = wire.PolicyEdit{Outcome: "invalid"}
			return nil, noWrite
		}
		if p.revision(f) != expected {
			result.Outcome = "conflict"
			capture(f)
			return nil, noWrite
		}
		changed, err := applyDecisionRule(&f, subject, action, resource, change)
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

// ReadRule returns one exact rule with its provenance. Callers authorize first.
func (p *DecisionPolicy) ReadRule(subject wire.Subject, action, resource string) wire.RuleRead {
	s, err := NormalizeDecisionSubject(subject)
	if err != nil || !ValidDecisionQuery(action, resource) {
		return wire.RuleRead{Outcome: wire.RuleReadOutcomeInvalid}
	}
	f, revision, err := p.readDecision()
	if err != nil {
		return wire.RuleRead{Outcome: wire.RuleReadOutcomeUnavailable}
	}
	key := ruleKey(decisionRule{Subject: s, Action: action, Resource: resource})
	for _, r := range f.Rules {
		if ruleKey(r) != key {
			continue
		}
		record := wire.RuleRecord{Rule: publicRule(r), SetBy: r.SetBy, SetAt: r.SetAt, Why: r.Why, Expires: r.Expires}
		outcome := wire.RuleReadOutcomeFound
		if expired(r, p.now()) {
			outcome = wire.RuleReadOutcomeExpired
		}
		return wire.RuleRead{Outcome: outcome, Revision: revision, Record: &record}
	}
	return wire.RuleRead{Outcome: wire.RuleReadOutcomeUnknown, Revision: revision}
}

// EditAction conditionally registers or retires one catalogue action, recording
// by as registrant. Retirement removes every rule naming the action. Seeded
// actions cannot be retired.
func (p *DecisionPolicy) EditAction(expected, action string, register bool, by wire.Subject, authorize func() error) (wire.ActionEdit, error) {
	by, err := NormalizeDecisionSubject(by)
	valid := boundedDecisionString(action, 128)
	if register {
		valid = ValidActionName(action)
	}
	if err != nil || !valid || !boundedDecisionString(expected, 128) {
		return wire.ActionEdit{Outcome: wire.ActionEditOutcomeInvalid}, nil
	}
	if authorize == nil {
		return wire.ActionEdit{Outcome: wire.ActionEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err = p.regular(); err != nil {
		return wire.ActionEdit{Outcome: wire.ActionEditOutcomeUnavailable}, err
	}
	result := wire.ActionEdit{}
	noWrite := errors.New("rights: catalogue edit without write")
	capture := func(f decisionFile) {
		result.Revision = p.revision(f)
		for _, a := range f.Actions {
			if a.Action == action {
				entry := wire.CatalogEntry{Action: a.Action, RegisteredBy: a.By, RegisteredAt: a.At}
				result.Current = &entry
				break
			}
		}
	}
	at := stamp(p.now())
	err = cas.ChangeLimit(p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) {
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		catalogue := p.catalogue(f)
		if !register && slices.Contains(p.seed, action) {
			result = wire.ActionEdit{Outcome: wire.ActionEditOutcomeInvalid}
			return nil, noWrite
		}
		if p.revision(f) != expected {
			result.Outcome = wire.ActionEditOutcomeConflict
			capture(f)
			return nil, noWrite
		}
		if register {
			if slices.Contains(catalogue, action) {
				result.Outcome = wire.ActionEditOutcomeApplied
				capture(f)
				return nil, noWrite
			}
			if len(catalogue) >= MaxDecisionActions {
				result = wire.ActionEdit{Outcome: wire.ActionEditOutcomeExhausted}
				return nil, noWrite
			}
			addAction(&f, registeredAction{Action: action, By: by, At: at})
		} else {
			index := slices.IndexFunc(f.Actions, func(a registeredAction) bool { return a.Action == action })
			if index < 0 {
				result = wire.ActionEdit{Outcome: wire.ActionEditOutcomeUnknown, Revision: p.revision(f)}
				return nil, noWrite
			}
			f.Actions = slices.Delete(f.Actions, index, index+1)
			if len(f.Actions) == 0 {
				f.Actions = nil
			}
			f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return r.Action == action })
			if len(f.Rules) == 0 {
				f.Rules = nil
			}
		}
		result.Outcome = wire.ActionEditOutcomeApplied
		capture(f)
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if err != nil {
		return wire.ActionEdit{Outcome: wire.ActionEditOutcomeUnavailable}, err
	}
	return result, nil
}
