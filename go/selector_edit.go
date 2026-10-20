package rights

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

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
	return boundedDecisionString(expected, 128) && edit.TTL >= 0 && edit.TTL <= MaxRuleTTL && edit.TTL%time.Millisecond == 0 && validWhy(edit.Why) && validStoredSubject(edit.By)
}
func (p *DecisionPolicy) SetSelectorRuleContext(ctx context.Context, expected string, rule wire.SelectorRule, edit RuleEdit, authorize func() error) (wire.SelectorEdit, error) {
	s, e := writableSubject(rule.Subject)
	if e != nil {
		return wire.SelectorEdit{Outcome: wire.PolicyEditOutcomeInvalid, Current: []wire.SelectorRuleRecord{}}, e
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
	result := refuse(wire.PolicyEditOutcomeUnavailable)
	noWrite := errors.New("rights: selector no write")
	err := p.changeContext(ctx, func(data []byte) ([]byte, error) {
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
				if p.consentBlockForSelection(f, revision, change.subject, s, now) {
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
