package rights

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// legacyPermissionRules validates a complete trusted effect without installing
// a new typed profile. Its One targets are canonical exact-resource strings.
func (p *DecisionPolicy) legacyPermissionRules(effect wire.PermissionEffect) ([]wire.PolicyRule, bool) {
	if p.Definitions == nil || effect.Bundle != nil || len(effect.Selections) == 0 || len(effect.Selections) > MaxPermissionEffect {
		return nil, false
	}
	subject, err := writableSubject(effect.Subject)
	if err != nil {
		return nil, false
	}
	var rules []wire.PolicyRule
	for _, s := range effect.Selections {
		var resource string
		definition, known := p.Definitions.Lookup(s.Permission.Action)
		if !known || !definition.Served || definition.ResourceProfile != LegacyExactResourceProfile || s.Permission.ResourceProfile != LegacyExactResourceProfile || s.Selector.Kind != wire.ResourceSelectorKindOne || json.Unmarshal(s.Selector.Target, &resource) != nil || !p.Definitions.ValidResource(s.Permission.Action, resource) {
			return nil, false
		}
		raw, _ := json.Marshal(resource)
		if !bytes.Equal(raw, s.Selector.Target) || IsMetaRule(s.Permission.Action, resource) {
			return nil, false
		}
		rules = append(rules, wire.PolicyRule{Subject: subject, Action: s.Permission.Action, Resource: resource, Permit: true})
	}
	if !legacySameResource(rules) && !legacyFanout(rules) {
		return nil, false
	}
	return rules, true
}

// legacySameResource is the original complete shape: several actions on one
// exact resource, in strictly increasing action order.
func legacySameResource(rules []wire.PolicyRule) bool {
	for i := 1; i < len(rules); i++ {
		if rules[i].Resource != rules[0].Resource || rules[i-1].Action >= rules[i].Action {
			return false
		}
	}
	return true
}

// legacyFanout is one action on several exact resources in strictly
// increasing resource order: one answer that writes one rule per target,
// each stored and removable on its own.
func legacyFanout(rules []wire.PolicyRule) bool {
	if len(rules) < 2 {
		return false
	}
	for i := 1; i < len(rules); i++ {
		if rules[i].Action != rules[0].Action || rules[i-1].Resource >= rules[i].Resource {
			return false
		}
	}
	return true
}

func legacyTargets(rules []wire.PolicyRule) []answerTarget {
	out := make([]answerTarget, 0, len(rules))
	for _, r := range rules {
		out = append(out, answerTarget{r.Action, r.Resource})
	}
	return out
}

// CheckLegacyPermissionEffectContext evaluates all exact members at one policy
// snapshot. It is the complete-effect companion of CheckLegacyOperationContext.
func (p *DecisionPolicy) CheckLegacyPermissionEffectContext(ctx context.Context, effect wire.PermissionEffect, expected string) wire.BatchDecision {
	rules, ok := p.legacyPermissionRules(effect)
	if !ok {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeInvalid, Outcomes: []wire.DecisionOutcome{}}
	}
	f, revision, err := p.readDecisionContext(ctx)
	if err != nil {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
	}
	if expected != "" && expected != revision {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeConflict, Revision: revision, Outcomes: []wire.DecisionOutcome{}}
	}
	out := wire.BatchDecision{Outcome: wire.BatchCheckOutcomeChecked, Revision: revision, Outcomes: []wire.DecisionOutcome{}}
	for _, r := range rules {
		decision := p.legacyOperationDecision(ctx, f, revision, r.Subject, wire.LegacyOperationRequest{LegacyAction: r.Action, LegacyResource: r.Resource}, p.now())
		if decision.Outcome == wire.DecisionOutcomeUnavailable {
			return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
		}
		out.Outcomes = append(out.Outcomes, decision.Outcome)
	}
	return out
}

func legacyEffectState(f decisionFile, rules []wire.PolicyRule) []wire.SelectorRuleRecord {
	out := []wire.SelectorRuleRecord{}
	key := keyOnce()
	for _, wanted := range rules {
		for _, r := range f.Rules {
			if sameTarget(r, wanted.Subject, wanted.Action, wanted.Resource, key) {
				target, _ := json.Marshal(r.Resource)
				out = append(out, wire.SelectorRuleRecord{Rule: wire.SelectorRule{Subject: r.Subject, Selection: wire.PermissionSelection{Permission: wire.PermissionKey{Action: r.Action, ResourceProfile: LegacyExactResourceProfile}, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: target}}, Permit: r.Permit}, SetBy: r.SetBy, SetAt: r.SetAt, Why: r.Why, Expires: r.Expires})
			}
		}
	}
	return out
}

func legacyEffectEdit(result wire.PolicyEdit, err error, current []wire.SelectorRuleRecord) (wire.SelectorEdit, error) {
	if err != nil {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeUnavailable, Current: []wire.SelectorRuleRecord{}}, err
	}
	if result.Outcome != wire.PolicyEditOutcomeApplied && result.Outcome != wire.PolicyEditOutcomeConflict {
		current = []wire.SelectorRuleRecord{}
	}
	return wire.SelectorEdit{Outcome: result.Outcome, Revision: result.Revision, Current: current}, nil
}

// ApplyLegacyPermissionEffect commits the Book-pinned exact effect and its
// completion receipt through the existing legacy policy mutation owner.
func (p *DecisionPolicy) ApplyLegacyPermissionEffect(ctx context.Context, expected string, effect wire.PermissionEffect, edit RuleEdit, id string, retained []string, authorize func() error) (wire.SelectorEdit, error) {
	rules, ok := p.legacyPermissionRules(effect)
	receipt, valid := firstUseAllowReceipt(id, retained)
	if !ok || !valid || edit.TTL != 0 || !edit.Deadline.IsZero() {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	permit := true
	edit.Permit, edit.QuestionID, edit.PreserveOtherSetter = &permit, id, true
	current := []wire.SelectorRuleRecord{}
	result, err := p.changeRulesBounded(ctx, expected, rules, edit, authorize, receipt, false, legacyFanout(rules), MaxPermissionEffect, func(f decisionFile, _ string) { current = legacyEffectState(f, rules) })
	return legacyEffectEdit(result, err, current)
}

// ChangeLegacyPermissionEffectUnderAnswer atomically checks/renews the live
// enrollment and writes every member with its stamped expiry and answerer.
func (p *DecisionPolicy) ChangeLegacyPermissionEffectUnderAnswer(ctx context.Context, holder wire.Subject, effect wire.PermissionEffect, why, id string, allow bool, authorize func() error) (wire.SelectorEdit, error) {
	rules, ok := p.legacyPermissionRules(effect)
	if !ok || !validAnswerID(id) || legacyFanout(rules) {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	var actions []string
	if allow {
		for _, r := range rules {
			actions = append(actions, r.Action)
		}
	} else {
		id = ""
	}
	current := []wire.SelectorRuleRecord{}
	result, err := p.changeRulesUnderAnswer(ctx, holder, rules[0].Subject, actions, rules[0].Resource, why, id, authorize, MaxPermissionEffect, func(f decisionFile, _ string) { current = legacyEffectState(f, rules) })
	return legacyEffectEdit(result, err, current)
}

// UndoLegacyPermissionEffect removes only the current rules carrying this
// retained occurrence ID. A responder actor, when supplied, must still match.
func (p *DecisionPolicy) UndoLegacyPermissionEffect(ctx context.Context, expected string, effect wire.PermissionEffect, answerer *wire.Subject, id string, authorize func() error) (wire.SelectorEdit, error) {
	rules, ok := p.legacyPermissionRules(effect)
	if !ok || !validAnswerID(id) {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	holder := wire.Subject{}
	if answerer != nil {
		holder = *answerer
	}
	current := []wire.SelectorRuleRecord{}
	result, err := p.revokeAnswerPermits(ctx, expected, holder, rules[0].Subject, legacyTargets(rules), id, authorize, MaxPermissionEffect, answerer == nil, func(f decisionFile, _ string) { current = legacyEffectState(f, rules) })
	return legacyEffectEdit(result, err, current)
}

type selectorChange struct {
	selections   []wire.PermissionSelection
	subject      wire.Subject
	permit       *bool
	edit         RuleEdit
	expansion    *wire.BundleExpansion
	removeOrigin string
	undoID       string
	receipt      *operatorAllowReceipt
}

func validSelectorEdit(expected string, edit RuleEdit) bool {
	return boundedDecisionString(expected, 128) && edit.TTL >= 0 && edit.TTL <= MaxRuleTTL && edit.TTL%time.Millisecond == 0 && validWhy(edit.Why) && validStoredActor(edit.By)
}
func (p *DecisionPolicy) SetSelectorRuleContext(ctx context.Context, expected string, rule wire.SelectorRule, edit RuleEdit, authorize func() error) (wire.SelectorEdit, error) {
	s, e := writableSubject(rule.Subject)
	if e != nil {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, e
	}
	if remoteSubject(s) && rule.Selection.Selector.Kind != wire.ResourceSelectorKindOne {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	selection, e := p.Definitions.PrepareSelection(rule.Selection)
	if e != nil {
		if errors.Is(e, ErrPermissionUnavailable) {
			return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeUnavailable, Current: []wire.SelectorRuleRecord{}}, nil
		}
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	permit := rule.Permit
	return p.changeSelectors(ctx, expected, selectorChange{subject: s, selections: []wire.PermissionSelection{selection}, permit: &permit, edit: edit}, authorize)
}

// Removal addresses exact retained target bytes; it never resolves a program
// again. Operator admission makes this read/removal assertion non-granting.
func (p *DecisionPolicy) RemoveSelectorRuleContext(ctx context.Context, expected string, subject wire.Subject, selection wire.PermissionSelection, edit RuleEdit, authorize func() error) (wire.SelectorEdit, error) {
	s, e := writableSubject(subject)
	if e != nil {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, e
	}
	if p.Definitions == nil || !p.Definitions.ValidStoredSelection(selection) {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	return p.changeSelectors(ctx, expected, selectorChange{subject: s, selections: []wire.PermissionSelection{cloneSelection(selection)}, edit: edit}, authorize)
}
func (p *DecisionPolicy) ApplyBundleContext(ctx context.Context, expected string, subject wire.Subject, ref string, selector wire.ResourceSelector, edit RuleEdit, authorize func() error) (wire.SelectorEdit, error) {
	effect, e := p.Definitions.PreparePermissionEffect(subject, nil, ref, &selector)
	if e != nil {
		if errors.Is(e, ErrPermissionUnavailable) {
			return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeUnavailable, Current: []wire.SelectorRuleRecord{}}, nil
		}
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	permit := true
	return p.changeSelectors(ctx, expected, selectorChange{subject: effect.Subject, selections: effect.Selections, permit: &permit, edit: edit, expansion: effect.Bundle}, authorize)
}
func (p *DecisionPolicy) RemoveBundleContext(ctx context.Context, expected string, subject wire.Subject, id string, edit RuleEdit, authorize func() error) (wire.SelectorEdit, error) {
	s, e := writableSubject(subject)
	if e != nil || !boundedDecisionString(id, 128) {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, e
	}
	return p.changeSelectors(ctx, expected, selectorChange{subject: s, edit: edit, removeOrigin: id}, authorize)
}

// ApplyPermissionEffect takes only the trusted pinned Book's canonical effect.
// Completion proof and every member commit together; revoked effects never replay.
func (p *DecisionPolicy) ApplyPermissionEffect(ctx context.Context, expected string, effect wire.PermissionEffect, edit RuleEdit, id string, retained []string, authorize func() error) (wire.SelectorEdit, error) {
	if p.Definitions == nil || !p.Definitions.ValidPermissionEffect(effect) || !validAnswerID(id) || len(retained) > MaxAppliedOperatorAnswers || !slices.Contains(retained, id) {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	retained = slices.Clone(retained)
	slices.Sort(retained)
	for i, v := range retained {
		if !validAnswerID(v) || i > 0 && retained[i-1] == v {
			return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
		}
	}
	permit := true
	edit.QuestionID = id
	edit.PreserveOtherSetter = true
	return p.changeSelectors(ctx, expected, selectorChange{subject: effect.Subject, selections: cloneSelections(effect.Selections), permit: &permit, edit: edit, expansion: effect.Bundle, receipt: &operatorAllowReceipt{id, retained}}, authorize)
}
func (p *DecisionPolicy) UndoPermissionEffect(ctx context.Context, expected string, effect wire.PermissionEffect, operator wire.Subject, id string, authorize func() error) (wire.SelectorEdit, error) {
	if p.Definitions == nil || !p.Definitions.ValidStoredPermissionEffect(effect) || !validAnswerID(id) {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, nil
	}
	return p.changeSelectors(ctx, expected, selectorChange{subject: effect.Subject, selections: cloneSelections(effect.Selections), edit: RuleEdit{By: operator}, undoID: id}, authorize)
}
func (p *DecisionPolicy) AppliedPermissionEffect(id string) (bool, error) {
	f, _, e := p.readDecision()
	return slices.Contains(f.AppliedTypedAnswers, id), e
}

func (p *DecisionPolicy) changeSelectors(ctx context.Context, expected string, change selectorChange, authorize func() error) (wire.SelectorEdit, error) {
	refuse := func(out wire.PolicyEditOutcome) wire.SelectorEdit {
		return wire.SelectorEdit{Outcome: out, Current: []wire.SelectorRuleRecord{}}
	}
	if p.Definitions == nil || !validSelectorEdit(expected, change.edit) || !validStoredSubject(change.subject) || len(change.selections) > MaxPermissionEffect {
		return refuse(wire.PolicyEditOutcomeInvalid), nil
	}
	for i, s := range change.selections {
		if remoteSubject(change.subject) && s.Selector.Kind != wire.ResourceSelectorKindOne {
			return refuse(wire.PolicyEditOutcomeInvalid), nil
		}
		if !p.Definitions.ValidStoredSelection(s) || change.permit != nil && !p.Definitions.ValidSelection(s) || i > 0 && permissionKeyString(change.selections[i-1].Permission) >= permissionKeyString(s.Permission) {
			return refuse(wire.PolicyEditOutcomeInvalid), nil
		}
	}
	if authorize == nil {
		return refuse(wire.PolicyEditOutcomeUnavailable), errors.New("rights: operator admission required")
	}
	if e := p.regular(); e != nil {
		return refuse(wire.PolicyEditOutcomeUnavailable), e
	}
	guards := make([]func() error, 0, len(change.selections))
	for _, selection := range change.selections {
		guard, err := p.preparePermit(ctx, change.subject, selection, change.permit)
		if err != nil {
			return refuse(wire.PolicyEditOutcomeUnavailable), err
		}
		guards = append(guards, guard)
	}
	result := refuse(wire.PolicyEditOutcomeUnavailable)
	noWrite := errors.New("rights: selector no write")
	err := p.changeContext(ctx, func(data []byte) ([]byte, error) {
		for _, guard := range guards {
			if err := guard(); err != nil {
				return nil, err
			}
		}
		if e := authorize(); e != nil {
			return nil, e
		}
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		revision := p.revision(f)
		now := p.now()
		affected := func() []wire.SelectorRuleRecord {
			rows := []wire.SelectorRuleRecord{}
			for _, r := range f.SelectorRules {
				matches := change.removeOrigin != "" && r.OriginID == change.removeOrigin && p.sameSelectorSubject(r, change.subject, revision)
				for _, s := range change.selections {
					if p.sameSelector(r, change.subject, s, revision, true) {
						matches = true
						break
					}
				}
				if matches {
					rows = append(rows, p.publicSelectorRecord(f, r))
				}
			}
			return rows
		}
		if revision != expected || change.receipt != nil && slices.Contains(f.AppliedTypedAnswers, change.receipt.id) {
			result = wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: revision, Current: affected()}
			return nil, noWrite
		}
		for _, s := range change.selections {
			if !slices.Contains(p.catalogue(f), s.Permission.Action) {
				result = refuse(wire.PolicyEditOutcomeInvalid)
				return nil, noWrite
			}
		}
		ttl := change.edit.TTL
		if !change.edit.Deadline.IsZero() {
			if !now.Before(change.edit.Deadline) {
				return nil, ErrRuleDeadline
			}
			cap := change.edit.Deadline.Sub(now).Truncate(time.Millisecond) - time.Millisecond
			if cap < time.Millisecond {
				return nil, ErrRuleDeadline
			}
			if ttl == 0 || ttl > cap {
				ttl = cap
			}
		}
		before, _ := json.Marshal(f)
		originID := ""
		if change.expansion != nil {
			encoded, _ := json.Marshal(struct {
				Revision  string
				Subject   wire.Subject
				Expansion wire.BundleExpansion
				By        wire.Subject
				At        string
			}{revision, change.subject, cloneExpansion(*change.expansion), change.edit.By, stamp(now)})
			sum := sha256.Sum256(encoded)
			originID = "sha256:" + hex.EncodeToString(sum[:])
		}
		if change.edit.PreserveOtherSetter {
			for _, s := range change.selections {
				if blocked, ok := p.consentBlockForSelection(f, revision, change.subject, s, now); blocked || !ok {
					result = wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: revision, Current: affected()}
					return nil, noWrite
				}
				for _, r := range f.SelectorRules {
					if p.sameSelector(r, change.subject, s, revision, false) && !selectorExpired(r, now) && !r.Permit {
						result = wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: revision, Current: affected()}
						return nil, noWrite
					}
				}
			}
		}
		if change.removeOrigin != "" {
			f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(r selectorRule) bool {
				return r.OriginID == change.removeOrigin && p.sameSelectorSubject(r, change.subject, revision)
			})
		}
		removedUndo := false
		for _, s := range change.selections {
			if change.permit == nil {
				f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(r selectorRule) bool {
					if !p.sameSelector(r, change.subject, s, revision, true) {
						return false
					}
					if change.undoID != "" {
						if !r.Permit || selectorExpired(r, now) || r.QuestionID != change.undoID || !sameTarget(decisionRule{Subject: r.SetBy}, change.edit.By, "", "", p.decisionKeys(revision, change.edit.By.Program)) {
							return false
						}
						removedUndo = true
					}
					return true
				})
				continue
			}
			skip := false
			if change.edit.PreserveOtherSetter {
				for _, r := range f.SelectorRules {
					if p.sameSelector(r, change.subject, s, revision, false) && !selectorExpired(r, now) && r.Permit && !sameTarget(decisionRule{Subject: r.SetBy}, change.edit.By, "", "", p.decisionKeys(revision, change.edit.By.Program)) {
						skip = true
						break
					}
				}
			}
			if skip {
				continue
			}
			r := selectorRule{Subject: change.subject, Selection: cloneSelection(s), Permit: *change.permit, SetBy: change.edit.By, SetAt: stamp(now), Why: change.edit.Why, OriginID: originID, QuestionID: change.edit.QuestionID}
			if ttl > 0 {
				r.Expires = stamp(now.Add(ttl))
			}
			unchanged := false
			for _, old := range f.SelectorRules {
				if p.sameSelector(old, change.subject, s, revision, false) && old.Permit == r.Permit && !selectorExpired(old, now) && old.Why == r.Why && old.Expires == r.Expires && old.OriginID == r.OriginID && old.QuestionID == r.QuestionID {
					unchanged = true
					break
				}
			}
			if unchanged {
				continue
			}
			f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(old selectorRule) bool { return p.sameSelector(old, change.subject, s, revision, false) })
			if len(f.Rules)+len(f.SelectorRules) >= MaxDecisionRules {
				return nil, errors.New("rights: combined rule capacity")
			}
			f.SelectorRules = append(f.SelectorRules, r)
		}
		if change.undoID != "" && !removedUndo {
			result = wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeConflict, Revision: revision, Current: affected()}
			return nil, noWrite
		}
		if change.expansion != nil {
			used := false
			for _, r := range f.SelectorRules {
				if r.OriginID == originID {
					used = true
					break
				}
			}
			if used {
				f.BundleOrigins = append(f.BundleOrigins, storedBundleOrigin{ID: originID, Expansion: cloneExpansion(*change.expansion)})
			}
		}
		if change.receipt != nil {
			f.AppliedTypedAnswers = slices.DeleteFunc(f.AppliedTypedAnswers, func(id string) bool { _, ok := slices.BinarySearch(change.receipt.retained, id); return !ok })
			if len(f.AppliedTypedAnswers)+len(f.AppliedOperatorAnswers) >= MaxAppliedOperatorAnswers {
				return nil, errors.New("rights: combined completion capacity")
			}
			f.AppliedTypedAnswers = append(f.AppliedTypedAnswers, change.receipt.id)
			slices.Sort(f.AppliedTypedAnswers)
		}
		pruneSelectorState(&f, now)
		sortSelectorState(&f)
		after, e := encodeSelectorState(f)
		if e != nil {
			return nil, e
		}
		if bytesEqual(before, after) {
			result = wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: revision, Current: affected()}
			return nil, noWrite
		}
		f.Profile = DecisionProfile
		if e = p.validateSelectorState(f); e != nil {
			return nil, e
		}
		after, e = encodeSelectorState(f)
		if e != nil {
			return nil, e
		}
		result = wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: p.revision(f), Current: affected()}
		if originID != "" {
			for _, o := range f.BundleOrigins {
				if o.ID == originID {
					v := wire.BundleOrigin{ID: o.ID, Expansion: cloneExpansion(o.Expansion)}
					result.BundleOrigin = &v
					break
				}
			}
		}
		return after, nil
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if err != nil {
		return refuse(wire.PolicyEditOutcomeUnavailable), err
	}
	return result, nil
}
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }
