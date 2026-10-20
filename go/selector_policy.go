package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

type selectorRule struct {
	Subject    wire.Subject             `json:"subject"`
	Selection  wire.PermissionSelection `json:"selection"`
	Permit     bool                     `json:"permit"`
	SetBy      wire.Subject             `json:"set_by"`
	SetAt      string                   `json:"set_at"`
	Why        string                   `json:"why,omitempty"`
	Expires    string                   `json:"expires,omitempty"`
	OriginID   string                   `json:"origin_id,omitempty"`
	QuestionID string                   `json:"answer_question_id,omitempty"`
}
type storedBundleOrigin struct {
	ID        string               `json:"id"`
	Expansion wire.BundleExpansion `json:"expansion"`
}

func selectorRuleKey(r selectorRule) string {
	return r.Subject.Account + "\x00" + r.Subject.Program + "\x00" + permissionKeyString(r.Selection.Permission) + "\x00" + r.Selection.Selector.Kind.String() + "\x00" + string(r.Selection.Selector.Target)
}
func selectorExpired(r selectorRule, now time.Time) bool {
	return expired(decisionRule{Expires: r.Expires}, now)
}
func (p *DecisionPolicy) sameSelectorSubject(r selectorRule, s wire.Subject, revision string) bool {
	return sameTarget(decisionRule{Subject: r.Subject}, s, "", "", p.decisionKeys(revision, s.Program))
}
func (p *DecisionPolicy) sameSelector(r selectorRule, s wire.Subject, selection wire.PermissionSelection, revision string, exact bool) bool {
	if r.Selection.Permission != selection.Permission || r.Selection.Selector.Kind != selection.Selector.Kind || !p.sameSelectorSubject(r, s, revision) {
		return false
	}
	if r.Selection.Selector.Kind == wire.ResourceSelectorKindAll {
		return true
	}
	if exact {
		return bytes.Equal(r.Selection.Selector.Target, selection.Selector.Target)
	}
	return p.Definitions.sameTarget(selection.Permission, r.Selection.Selector.Target, selection.Selector.Target)
}
func (p *DecisionPolicy) publicSelectorRecord(f decisionFile, r selectorRule) wire.SelectorRuleRecord {
	v := wire.SelectorRuleRecord{Rule: wire.SelectorRule{Subject: r.Subject, Selection: cloneSelection(r.Selection), Permit: r.Permit}, SetBy: r.SetBy, SetAt: r.SetAt, Why: r.Why, Expires: r.Expires}
	if r.OriginID != "" {
		for _, o := range f.BundleOrigins {
			if o.ID == r.OriginID {
				x := wire.BundleOrigin{ID: o.ID, Expansion: cloneExpansion(o.Expansion)}
				v.BundleOrigin = &x
				break
			}
		}
	}
	return v
}
func (p *DecisionPolicy) validateSelectorState(f decisionFile) error {
	if len(f.Rules)+len(f.SelectorRules) > MaxDecisionRules || len(f.BundleOrigins) > MaxDecisionRules || len(f.AppliedOperatorAnswers)+len(f.AppliedTypedAnswers) > MaxAppliedOperatorAnswers {
		return errors.New("rights: combined state bound")
	}
	if profileVersion(f.Profile) < 6 && (len(f.SelectorRules) != 0 || len(f.BundleOrigins) != 0 || len(f.AppliedTypedAnswers) != 0) {
		return errors.New("rights: typed state in legacy profile")
	}
	for i, id := range f.AppliedTypedAnswers {
		if !validAnswerID(id) || i > 0 && f.AppliedTypedAnswers[i-1] >= id {
			return errors.New("rights: invalid typed completion")
		}
	}
	origins := map[string]bool{}
	for i, o := range f.BundleOrigins {
		if !boundedDecisionString(o.ID, 128) || i > 0 && f.BundleOrigins[i-1].ID >= o.ID || p.Definitions == nil || !p.Definitions.ValidateExpansion(o.Expansion) {
			return errors.New("rights: invalid bundle origin")
		}
		origins[o.ID] = true
	}
	previous := ""
	catalog := p.catalogue(f)
	for _, r := range f.SelectorRules {
		key := selectorRuleKey(r)
		if !validStoredSubject(r.Subject) || !validStoredSubject(r.SetBy) || !validStamp(r.SetAt) || !validWhy(r.Why) || r.Expires != "" && !validStamp(r.Expires) || !slices.Contains(catalog, r.Selection.Permission.Action) || p.Definitions == nil || !p.Definitions.ValidStoredSelection(r.Selection) || key <= previous || r.OriginID != "" && (!r.Permit || !origins[r.OriginID]) || r.QuestionID != "" && (!r.Permit || !validAnswerID(r.QuestionID)) {
			return errors.New("rights: invalid selector state")
		}
		previous = key
	}
	return nil
}
func pruneSelectorState(f *decisionFile, now time.Time) {
	f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(r selectorRule) bool { return selectorExpired(r, now) })
	if len(f.SelectorRules) == 0 {
		f.SelectorRules = nil
	}
	pruneOrigins(f)
}
func pruneOrigins(f *decisionFile) {
	used := map[string]bool{}
	for _, r := range f.SelectorRules {
		if r.OriginID != "" {
			used[r.OriginID] = true
		}
	}
	f.BundleOrigins = slices.DeleteFunc(f.BundleOrigins, func(o storedBundleOrigin) bool { return !used[o.ID] })
	if len(f.BundleOrigins) == 0 {
		f.BundleOrigins = nil
	}
}

func (p *DecisionPolicy) checkBatchInput(req wire.CheckBatchRequest) bool {
	if p.Definitions == nil || p.Definitions.selectors == nil || len(req.Resources) > MaxBatchResources || len(req.Resources) == 0 && req.CollectionAdmission == nil || req.ExpectedRevision != "" && !boundedDecisionString(req.ExpectedRevision, 128) {
		return false
	}
	if req.CollectionAdmission != nil && !p.Definitions.ValidSelection(wire.PermissionSelection{Permission: *req.CollectionAdmission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindAll}}) {
		return false
	}
	for _, r := range req.Resources {
		if !p.Definitions.ValidConcrete(r) {
			return false
		}
	}
	if len(wire.EncodeCheckBatchRequest(&req)) > MaxSelectorFrameBytes {
		return false
	}
	return true
}

// CheckBatchContext is quiet, receiver-canonical evaluation. One immutable
// snapshot and one service clock sample decide all resources; that read is the
// authority linearization boundary. No provider callback or Ask is made.
func (p *DecisionPolicy) CheckBatchContext(ctx context.Context, subject wire.Subject, req wire.CheckBatchRequest) wire.BatchDecision {
	if p.Definitions == nil || !p.Definitions.HasSelectors() {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
	}
	for _, r := range req.Resources {
		selection := wire.PermissionSelection{Permission: r.Permission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: r.Target}}
		if p.Definitions.ValidStoredSelection(selection) && !p.Definitions.ValidSelection(selection) {
			return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
		}
	}
	if req.CollectionAdmission != nil {
		selection := wire.PermissionSelection{Permission: *req.CollectionAdmission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindAll}}
		if p.Definitions.ValidStoredSelection(selection) && !p.Definitions.ValidSelection(selection) {
			return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
		}
	}
	s, e := NormalizeDecisionSubject(subject)
	if e != nil || !p.checkBatchInput(req) {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeInvalid, Outcomes: []wire.DecisionOutcome{}}
	}
	f, revision, e := p.readDecisionContext(ctx)
	if e != nil {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
	}
	if req.ExpectedRevision != "" && req.ExpectedRevision != revision {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeConflict, Revision: revision, Outcomes: []wire.DecisionOutcome{}}
	}
	now := p.now()
	out := wire.BatchDecision{Outcome: wire.BatchCheckOutcomeChecked, Revision: revision, Outcomes: make([]wire.DecisionOutcome, len(req.Resources))}
	if req.CollectionAdmission != nil {
		v := p.typedDecision(f, revision, s, *req.CollectionAdmission, nil, true, now)
		out.CollectionOutcome = &v
	}
	for i, r := range req.Resources {
		out.Outcomes[i] = p.typedDecision(f, revision, s, r.Permission, r.Target, false, now)
	}
	return out
}

// CheckPermissionEffectContext is consent admission, not collection execution.
// An All proposal intersecting a live explicit block refuses without exposing
// blocked target names. Normal CheckBatch collection admission keeps One blocks
// as per-concrete restrictions. Both paths use the shared owner and one snapshot.
func (p *DecisionPolicy) CheckPermissionEffectContext(ctx context.Context, effect wire.PermissionEffect, expected string) wire.BatchDecision {
	if p.Definitions == nil || !p.Definitions.ValidPermissionEffect(effect) || expected != "" && !boundedDecisionString(expected, 128) {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeInvalid, Outcomes: []wire.DecisionOutcome{}}
	}
	s, e := NormalizeDecisionSubject(effect.Subject)
	if e != nil {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeInvalid, Outcomes: []wire.DecisionOutcome{}}
	}
	f, revision, e := p.readDecisionContext(ctx)
	if e != nil {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeUnavailable, Outcomes: []wire.DecisionOutcome{}}
	}
	if expected != "" && expected != revision {
		return wire.BatchDecision{Outcome: wire.BatchCheckOutcomeConflict, Revision: revision, Outcomes: []wire.DecisionOutcome{}}
	}
	now := p.now()
	out := wire.BatchDecision{Outcome: wire.BatchCheckOutcomeChecked, Revision: revision, Outcomes: make([]wire.DecisionOutcome, len(effect.Selections))}
	for i, selection := range effect.Selections {
		collection := selection.Selector.Kind == wire.ResourceSelectorKindAll
		outcome := p.typedDecision(f, revision, s, selection.Permission, selection.Selector.Target, collection, now)
		if p.consentBlockForSelection(f, revision, s, selection, now) {
			outcome = wire.DecisionOutcomeDenied
		}
		out.Outcomes[i] = outcome
	}
	return out
}

// Consent admission and its atomic completion use the same live block
// intersection at their respective single policy snapshots.
func (p *DecisionPolicy) consentBlockForSelection(f decisionFile, revision string, s wire.Subject, selection wire.PermissionSelection, now time.Time) bool {
	collection := selection.Selector.Kind == wire.ResourceSelectorKindAll
	if p.legacyBlockForTyped(f, revision, s, selection.Permission, selection.Selector.Target, collection, now) {
		return true
	}
	for _, r := range f.SelectorRules {
		if !r.Permit && r.Selection.Permission == selection.Permission && !selectorExpired(r, now) && p.sameSelectorSubject(r, s, revision) && (collection || r.Selection.Selector.Kind == wire.ResourceSelectorKindAll || p.Definitions.sameTarget(selection.Permission, r.Selection.Selector.Target, selection.Selector.Target)) {
			return true
		}
	}
	if collection && p.Definitions.selectors != nil {
		for _, link := range p.Definitions.selectors.equivalents {
			if link.Permission != selection.Permission {
				continue
			}
			for _, r := range f.Rules {
				if !r.Permit && r.Action == link.Action && !expired(r, now) && sameTarget(decisionRule{Subject: r.Subject}, s, "", "", p.decisionKeys(revision, s.Program)) {
					if _, ok := equivalenceProjection(link, r.Resource); ok {
						return true
					}
				}
			}
		}
	}
	return false
}
func (p *DecisionPolicy) DefinitionSnapshotContext(ctx context.Context) (string, []wire.SelectorPermissionDefinition, []wire.PermissionBundleDefinition, error) {
	_, revision, e := p.readDecisionContext(ctx)
	if e != nil {
		return "", nil, nil, e
	}
	if p.Definitions == nil || !p.Definitions.HasSelectors() {
		return "", nil, nil, errors.New("rights: selector catalogue unavailable")
	}
	return revision, p.Definitions.SelectorDefinitions(), p.Definitions.PermissionBundles(), nil
}
func (p *DecisionPolicy) typedDecision(f decisionFile, revision string, s wire.Subject, k wire.PermissionKey, target []byte, collection bool, now time.Time) wire.DecisionOutcome {
	if !slices.Contains(p.catalogue(f), k.Action) {
		return wire.DecisionOutcomeUnknownAction
	}
	if p.legacyBlockForTyped(f, revision, s, k, target, collection, now) {
		return wire.DecisionOutcomeDenied
	}
	permit := false
	for _, r := range f.SelectorRules {
		if r.Selection.Permission != k || selectorExpired(r, now) || !p.sameSelectorSubject(r, s, revision) {
			continue
		}
		matches := r.Selection.Selector.Kind == wire.ResourceSelectorKindAll || !collection && p.Definitions.sameTarget(k, r.Selection.Selector.Target, target)
		if !matches {
			continue
		}
		if !r.Permit {
			return wire.DecisionOutcomeDenied
		}
		permit = true
	}
	if permit {
		return wire.DecisionOutcomePermitted
	}
	return wire.DecisionOutcomeNotGranted
}
func equivalenceProjection(e LegacyEquivalence, resource string) ([]byte, bool) {
	if e.Resource != "" {
		return nil, e.Resource == resource
	}
	return e.Concrete(resource)
}
func (p *DecisionPolicy) legacyBlockForTyped(f decisionFile, revision string, s wire.Subject, k wire.PermissionKey, target []byte, collection bool, now time.Time) bool {
	if p.Definitions == nil || p.Definitions.selectors == nil {
		return false
	}
	for _, e := range p.Definitions.selectors.equivalents {
		if e.Permission != k {
			continue
		}
		for _, r := range f.Rules {
			if r.Permit || r.Action != e.Action || expired(r, now) || !sameTarget(decisionRule{Subject: r.Subject}, s, "", "", p.decisionKeys(revision, s.Program)) {
				continue
			}
			mapped, ok := equivalenceProjection(e, r.Resource)
			if !ok {
				continue
			}
			if mapped == nil || !collection && p.Definitions.sameTarget(k, mapped, target) {
				return true
			}
		}
	}
	return false
}
func (p *DecisionPolicy) legacyOperationValid(req wire.LegacyOperationRequest) bool {
	if !ValidDecisionQuery(req.LegacyAction, req.LegacyResource) {
		return false
	}
	if req.ConcreteOperation == nil {
		return true
	}
	if p.Definitions == nil || p.Definitions.selectors == nil || !p.Definitions.ValidConcrete(*req.ConcreteOperation) {
		return false
	}
	for _, e := range p.Definitions.selectors.equivalents {
		if e.Action != req.LegacyAction || e.Permission != req.ConcreteOperation.Permission {
			continue
		}
		target, ok := equivalenceProjection(e, req.LegacyResource)
		if ok && (target == nil || p.Definitions.sameTarget(e.Permission, target, req.ConcreteOperation.Target)) {
			return true
		}
	}
	return false
}
func (p *DecisionPolicy) typedBlockForLegacy(f decisionFile, revision string, s wire.Subject, req wire.LegacyOperationRequest, now time.Time) bool {
	if p.Definitions == nil || p.Definitions.selectors == nil {
		return false
	}
	for _, e := range p.Definitions.selectors.equivalents {
		if e.Action != req.LegacyAction || req.ConcreteOperation != nil && e.Permission != req.ConcreteOperation.Permission {
			continue
		}
		target, ok := equivalenceProjection(e, req.LegacyResource)
		if !ok {
			continue
		}
		if req.ConcreteOperation != nil {
			target = req.ConcreteOperation.Target
		}
		for _, r := range f.SelectorRules {
			if r.Permit || r.Selection.Permission != e.Permission || selectorExpired(r, now) || !p.sameSelectorSubject(r, s, revision) {
				continue
			}
			if target == nil || r.Selection.Selector.Kind == wire.ResourceSelectorKindAll || p.Definitions.sameTarget(e.Permission, r.Selection.Selector.Target, target) {
				return true
			}
		}
	}
	return false
}

// CheckLegacyOperationContext requires original exact authority and imports only
// live equivalent blocks. A missing concrete effect conservatively checks the
// whole old collection. Receivers admit/validate actual membership before calling.
func (p *DecisionPolicy) CheckLegacyOperationContext(ctx context.Context, subject wire.Subject, req wire.LegacyOperationRequest) wire.Decision {
	s, e := NormalizeDecisionSubject(subject)
	if e != nil || !p.legacyOperationValid(req) {
		return wire.Decision{Outcome: wire.DecisionOutcomeInvalid}
	}
	f, revision, e := p.readDecisionContext(ctx)
	if e != nil {
		return wire.Decision{Outcome: wire.DecisionOutcomeUnavailable}
	}
	return p.legacyOperationDecision(f, revision, s, req, p.now())
}
func (p *DecisionPolicy) legacyOperationDecision(f decisionFile, revision string, s wire.Subject, req wire.LegacyOperationRequest, now time.Time) wire.Decision {
	return p.legacyOperationExplained(f, revision, s, req, now).decision()
}

// legacyExplanation is one legacy decision with the step that decided it
// (RIGHTS-O14). The decision and the explanation an operator reads are the
// same evaluation.
type legacyExplanation struct {
	wire.DecisionExplanation
}

func decisionSource(s wire.DecisionSource) *wire.DecisionSource { return &s }

func (e legacyExplanation) decision() wire.Decision {
	return wire.Decision{Outcome: e.Outcome, PolicyRevision: e.PolicyRevision}
}

func (p *DecisionPolicy) legacyOperationExplained(f decisionFile, revision string, s wire.Subject, req wire.LegacyOperationRequest, now time.Time) legacyExplanation {
	out := legacyExplanation{wire.DecisionExplanation{Outcome: wire.DecisionOutcomeNotGranted, PolicyRevision: revision, Source: decisionSource(wire.DecisionSourceNone)}}
	if !slices.Contains(p.catalogue(f), req.LegacyAction) {
		out.Outcome = wire.DecisionOutcomeUnknownAction
		return out
	}
	if p.typedBlockForLegacy(f, revision, s, req, now) {
		out.Outcome, out.Source = wire.DecisionOutcomeDenied, decisionSource(wire.DecisionSourceTypedBlock)
		return out
	}
	if r, ok := decidingRule(f.Rules, s, req.LegacyAction, req.LegacyResource, now, p.decisionKeys(revision, s.Program)); ok && !expired(r, now) {
		out.Outcome, out.Source = wire.DecisionOutcomeDenied, decisionSource(wire.DecisionSourceOwnRule)
		if r.Permit {
			out.Outcome = wire.DecisionOutcomePermitted
		}
		return out
	}
	// No live rule of the program's own: an account-wide default may permit
	// (RIGHTS-R22).
	switch name, verdict := p.defaultFor(f, s, req.LegacyAction, req.LegacyResource); verdict {
	case defaultPermits:
		out.Outcome, out.Source, out.DefaultName = wire.DecisionOutcomePermitted, decisionSource(wire.DecisionSourceAccountDefault), name
	case defaultExcludesProgram:
		out.Source, out.DefaultName = decisionSource(wire.DecisionSourceDefaultExcluded), name
	}
	return out
}
func (p *DecisionPolicy) SelectorSnapshotContext(ctx context.Context) (string, []wire.SelectorRuleRecord, error) {
	f, revision, e := p.readDecisionContext(ctx)
	if e != nil {
		return "", nil, e
	}
	out := make([]wire.SelectorRuleRecord, 0, len(f.SelectorRules))
	for _, r := range f.SelectorRules {
		out = append(out, p.publicSelectorRecord(f, r))
	}
	return revision, out, nil
}
func (p *DecisionPolicy) ReadSelectorRuleContext(ctx context.Context, subject wire.Subject, selection wire.PermissionSelection) wire.SelectorRuleRead {
	s, e := NormalizeDecisionSubject(subject)
	if e != nil || p.Definitions == nil || !p.Definitions.ValidStoredSelection(selection) {
		return wire.SelectorRuleRead{Outcome: wire.RuleReadOutcomeInvalid}
	}
	f, revision, e := p.readDecisionContext(ctx)
	if e != nil {
		return wire.SelectorRuleRead{Outcome: wire.RuleReadOutcomeUnavailable}
	}
	out := wire.SelectorRuleRead{Outcome: wire.RuleReadOutcomeUnknown, Revision: revision}
	for _, r := range f.SelectorRules {
		if p.sameSelector(r, s, selection, revision, true) {
			v := p.publicSelectorRecord(f, r)
			out.Record = &v
			out.Outcome = wire.RuleReadOutcomeFound
			if selectorExpired(r, p.now()) {
				out.Outcome = wire.RuleReadOutcomeExpired
			}
			break
		}
	}
	return out
}
func sortSelectorState(f *decisionFile) {
	slices.SortFunc(f.SelectorRules, func(a, b selectorRule) int { return strings.Compare(selectorRuleKey(a), selectorRuleKey(b)) })
	slices.SortFunc(f.BundleOrigins, func(a, b storedBundleOrigin) int { return strings.Compare(a.ID, b.ID) })
}

// The private persistence format remains canonical JSON. Decode rejects unknown
// fields and canonical re-encoding catches duplicates. Target documents remain
// owning-codec bytes, not state-file-defined schemas.
func encodeSelectorState(f decisionFile) ([]byte, error) {
	data, e := json.Marshal(f)
	if e != nil || len(data) > MaxDecisionBytes {
		return nil, errors.New("rights: selector state byte bound")
	}
	return data, nil
}
