package rights

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	f = revisionContent(f)
	//unchecked: data only feeds the revision hash below, never a returned payload; its fields are plain marshalable data
	data, _ := json.Marshal(struct {
		Seed        []string     `json:"seed"`
		File        decisionFile `json:"file"`
		Definitions string       `json:"definitions,omitempty"`
		Defaults    string       `json:"defaults,omitempty"`
	}{p.seed, f, p.Definitions.DefinitionDigest(), p.defaultsDigest()})
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

// PolicyObservationState is an invalidation snapshot, with no permission lease.
// Stamp changes at commits and once per expiry boundary; Deadline is the next
// future boundary. The durable Revision stays unchanged when time alone passes.
type PolicyObservationState struct {
	Revision string
	Stamp    string
	Deadline time.Time
}

// ObservePolicyStateContext reads revision and all expiry boundaries from one
// immutable policy read. The service owns notifications and confirms authority.
func (p *DecisionPolicy) ObservePolicyStateContext(ctx context.Context) (PolicyObservationState, error) {
	f, revision, err := p.readDecisionContext(ctx)
	if err != nil {
		return PolicyObservationState{}, err
	}
	state := PolicyObservationState{Revision: revision}
	now := p.now()
	timerNow := time.Now()
	stamp := sha256.New()
	stamp.Write([]byte(revision))
	add := func(expires string) {
		if expires == "" {
			return
		}
		at, _ := time.Parse(StampFormat, expires) // Validated by the policy reader.
		if at.After(now) {
			stamp.Write([]byte{0})
			if state.Deadline.IsZero() || at.Before(state.Deadline) {
				state.Deadline = at
			}
		} else {
			stamp.Write([]byte{1})
		}
	}
	for _, rule := range f.Rules {
		add(rule.Expires)
	}
	for _, rule := range f.SelectorRules {
		add(rule.Expires)
	}
	// Gate owns real/monotonic timers; configured service clocks can have a
	// different epoch. Preserve the one policy-clock sample's remaining delay.
	if !state.Deadline.IsZero() {
		state.Deadline = timerNow.Add(state.Deadline.Sub(now))
	}
	state.Stamp = hex.EncodeToString(stamp.Sum(nil))
	return state, nil
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
	// PreserveOtherSetter is for bounded delegated answers, which may never
	// replace a person's live rule. Explicit operator edits leave it false.
	PreserveOtherSetter bool
	// Deadline bounds a delegated permit by its absolute delegation expiry,
	// re-evaluated at the actual in-lock edit time.
	Deadline time.Time
	// QuestionID identifies a trusted responder answer's exact effect. It is
	// private persisted provenance, never a public RuleRecord member.
	QuestionID string
}

// EditRule compares the expected revision and rechecks trusted authorization
// inside the existing CAS edit, recording the service's own subject. Native
// Set/Revoke remain explicit unconditional operator APIs.
func (p *DecisionPolicy) EditRule(expected string, subject wire.Subject, action, resource string, permit *bool, authorize func() error) (wire.PolicyEdit, error) {
	return p.ChangeRule(expected, subject, action, resource, RuleEdit{Permit: permit, By: p.native}, authorize)
}

// RemoveRemoteSubjectContext removes every legacy and typed rule for one exact
// remote subject in this receiving account. The runtime supplies live native
// operator admission; possession of a subject or policy is not authorization.
// Completion proofs survive removal so an old answered Allow cannot replay.
// A lost reply requires reconciliation before selecting another revision.
func (p *DecisionPolicy) RemoveRemoteSubjectContext(ctx context.Context, expected string, subject wire.Subject, authorize func() error) (wire.PolicyEdit, error) {
	s, err := NormalizeDecisionSubject(subject)
	if err != nil || !remoteSubject(s) || s.Account != p.native.Account || !boundedDecisionString(expected, 128) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, err
	}
	if authorize == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err = p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: remote removal without write")
	err = p.changeContext(ctx, func(data []byte) ([]byte, error) {
		result = wire.PolicyEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		revision := p.revision(f)
		if revision != expected {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: revision}
			return nil, noWrite
		}
		removedOrigins := map[string]bool{}
		legacy, typed := len(f.Rules), len(f.SelectorRules)
		f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return r.Subject == s })
		f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(r selectorRule) bool {
			if r.Subject != s {
				return false
			}
			if r.OriginID != "" {
				removedOrigins[r.OriginID] = true
			}
			return true
		})
		result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: revision}
		if legacy == len(f.Rules) && typed == len(f.SelectorRules) {
			return nil, noWrite
		}
		for _, r := range f.SelectorRules {
			delete(removedOrigins, r.OriginID)
		}
		f.BundleOrigins = slices.DeleteFunc(f.BundleOrigins, func(o storedBundleOrigin) bool { return removedOrigins[o.ID] })
		result.Revision = p.revision(f)
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

// ChangeRule is EditRule with provenance, reason and expiry. A stale revision
// always conflicts. An uncatalogued action or an out-of-bounds edit is invalid.
// A rule written for a program path that keeps an unresolved short alias is
// invalid and returns ErrUnresolvedShortName, which names the path.
func (p *DecisionPolicy) ChangeRule(expected string, subject wire.Subject, action, resource string, edit RuleEdit, authorize func() error) (wire.PolicyEdit, error) {
	return p.ChangeRuleContext(context.Background(), expected, subject, action, resource, edit, authorize)
}

// ChangeRuleContext is ChangeRule with the outer admission's cancellation.
func (p *DecisionPolicy) ChangeRuleContext(ctx context.Context, expected string, subject wire.Subject, action, resource string, edit RuleEdit, authorize func() error) (wire.PolicyEdit, error) {
	if edit.Permit != nil {
		return p.changeRules(ctx, expected, []wire.PolicyRule{{Subject: subject, Action: action, Resource: resource, Permit: *edit.Permit}}, edit, authorize, nil)
	}
	// A revoke names the stored rule as it is; a written rule's subject must
	// have a spelling that can still match once its file appears. The setter
	// is provenance and matches nothing.
	normalize := NormalizeDecisionSubject
	if edit.Permit != nil {
		normalize = writableSubject
	}
	subject, err := normalize(subject)
	if errors.Is(err, ErrUnresolvedShortName) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, err
	}
	by, byErr := normalizeActor(edit.By)
	if err != nil || byErr != nil || !ValidDecisionQuery(action, resource) || !boundedDecisionString(expected, 128) ||
		edit.TTL < 0 || edit.TTL > MaxRuleTTL || edit.TTL%time.Millisecond != 0 || !validWhy(edit.Why) || (edit.Permit == nil && (edit.TTL != 0 || edit.Why != "")) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if validMetaEdit(action, resource, edit.Permit, edit.TTL) != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if err := p.refuseHolder(subject, action, resource, edit.Permit); err != nil {
		if errors.Is(err, ErrMetaHolderUnavailable) {
			return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
		}
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if authorize == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err = p.regular(); err != nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	result := wire.PolicyEdit{}
	noWrite := errors.New("rights: policy edit without write")
	change := ruleChange{permit: edit.Permit, by: by, at: p.now(), ttl: edit.TTL, why: edit.Why, exact: edit.Exact}
	capture := func(f decisionFile) {
		result.Revision = p.revision(f)
		if r, found := decidingRule(f.Rules, subject, action, resource, change.at, keyOnce()); found {
			current := publicRule(r)
			result.Current = &current
		}
	}
	err = p.changeContext(ctx, func(data []byte) ([]byte, error) {
		result = wire.PolicyEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(p.catalogue(f), action) {
			result = wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}
			return nil, noWrite
		}
		if p.revision(f) != expected {
			result.Outcome = wire.PolicyEditOutcomeConflict
			capture(f)
			return nil, noWrite
		}
		changed, err := applyDecisionRule(&f, subject, action, resource, change)
		if err != nil {
			return nil, err
		}
		result.Outcome = wire.PolicyEditOutcomeApplied
		if changed {
			f.Profile = DecisionProfile
		}
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
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	return result, nil
}

// ReadRule returns the rule that decides one target, with its provenance:
// the rule Decide reads (decidingRule). Callers authorize first.
func (p *DecisionPolicy) ReadRule(subject wire.Subject, action, resource string) wire.RuleRead {
	s, err := NormalizeDecisionSubject(subject)
	if err != nil || !ValidDecisionQuery(action, resource) {
		return wire.RuleRead{Outcome: wire.RuleReadOutcomeInvalid}
	}
	f, revision, err := p.readDecision()
	if err != nil {
		return wire.RuleRead{Outcome: wire.RuleReadOutcomeUnavailable}
	}
	now := p.now()
	r, found := decidingRule(f.Rules, s, action, resource, now, p.decisionKeys(revision, s.Program))
	if !found {
		return wire.RuleRead{Outcome: wire.RuleReadOutcomeUnknown, Revision: revision}
	}
	record := wire.RuleRecord{Rule: publicRule(r), SetBy: r.SetBy, SetAt: r.SetAt, Why: r.Why, Expires: r.Expires}
	outcome := wire.RuleReadOutcomeFound
	if expired(r, now) {
		outcome = wire.RuleReadOutcomeExpired
	}
	return wire.RuleRead{Outcome: outcome, Revision: revision, Record: &record}
}

// ExplainForContext evaluates subject on one exact target as a decision does
// and reports the step that decided it (RIGHTS-O14): the same evaluation, so
// a program-identity match, a typed Block and the defaults read as they
// decide. It asks nobody and records nothing.
func (p *DecisionPolicy) ExplainForContext(ctx context.Context, subject wire.Subject, action, resource string) wire.DecisionExplanation {
	s, err := NormalizeDecisionSubject(subject)
	if err != nil || !ValidDecisionQuery(action, resource) {
		return wire.DecisionExplanation{Outcome: wire.DecisionOutcomeInvalid}
	}
	ctx, preparationErr := p.prepareMetaOperation(ctx, action, resource)
	if p.preparationStopsRead(ctx, preparationErr) {
		return wire.DecisionExplanation{Outcome: wire.DecisionOutcomeUnavailable}
	}
	f, revision, err := p.readDecisionContext(ctx)
	if err != nil {
		return wire.DecisionExplanation{Outcome: wire.DecisionOutcomeUnavailable}
	}
	return p.afterMetaPreparation(p.legacyOperationExplained(ctx, f, revision, s, wire.LegacyOperationRequest{LegacyAction: action, LegacyResource: resource}, p.now()), preparationErr).DecisionExplanation
}

// EditAction conditionally registers or retires one catalogue action, recording
// by as registrant. Retirement removes every rule naming the action. Seeded
// actions cannot be retired.
func (p *DecisionPolicy) EditAction(expected, action string, register bool, by wire.Subject, authorize func() error) (wire.ActionEdit, error) {
	by, err := normalizeActor(by)
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
	err = p.change(func(data []byte) ([]byte, error) {
		result = wire.ActionEdit{}
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
			f.Descriptions = slices.DeleteFunc(f.Descriptions, func(d publishedDescription) bool { return d.Description.Action == action })
			if len(f.Descriptions) == 0 {
				f.Descriptions = nil
			}
			if len(f.Actions) == 0 {
				f.Actions = nil
			}
			f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return r.Action == action })
			f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(r selectorRule) bool { return r.Selection.Permission.Action == action })
			pruneOrigins(&f)
			if len(f.Rules) == 0 {
				f.Rules = nil
			}
		}
		result.Outcome = wire.ActionEditOutcomeApplied
		f.Profile = DecisionProfile
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
