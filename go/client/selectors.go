package client

import (
	"context"
	"errors"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

type PermissionKey = wire.PermissionKey
type ResourceSelector = wire.ResourceSelector
type PermissionSelection = wire.PermissionSelection
type ConcreteResource = wire.ConcreteResource
type CheckBatchRequest = wire.CheckBatchRequest
type BatchDecision = wire.BatchDecision
type LegacyOperationRequest = wire.LegacyOperationRequest
type SelectorPermissionDefinition = wire.SelectorPermissionDefinition
type PermissionDefinition = wire.PermissionDefinition
type PermissionFirstUse = wire.PermissionFirstUse

const (
	PermissionFirstUseNone            = wire.PermissionFirstUseNone
	PermissionFirstUseExact           = wire.PermissionFirstUseExact
	PermissionFirstUseConsumingPaired = wire.PermissionFirstUseConsumingPaired
)

func PermissionFirstUseValues() []PermissionFirstUse { return wire.PermissionFirstUseValues() }

type PermissionDefinitionPage = wire.PermissionDefinitionPage
type PermissionBundleDefinition = wire.PermissionBundleDefinition
type PermissionBundlePage = wire.PermissionBundlePage
type BundleExpansion = wire.BundleExpansion
type PermissionEffect = wire.PermissionEffect
type SelectorRule = wire.SelectorRule
type BundleOrigin = wire.BundleOrigin
type SelectorRuleRecord = wire.SelectorRuleRecord
type SelectorRulePage = wire.SelectorRulePage
type SelectorRuleRead = wire.SelectorRuleRead
type SelectorEdit = wire.SelectorEdit
type ResourceSelectorKind = wire.ResourceSelectorKind

const (
	ResourceSelectorKindOne = wire.ResourceSelectorKindOne
	ResourceSelectorKindAll = wire.ResourceSelectorKindAll
)

func ResourceSelectorKindValues() []ResourceSelectorKind { return wire.ResourceSelectorKindValues() }

type BatchCheckOutcome = wire.BatchCheckOutcome

const (
	BatchCheckOutcomeChecked     = wire.BatchCheckOutcomeChecked
	BatchCheckOutcomeConflict    = wire.BatchCheckOutcomeConflict
	BatchCheckOutcomeInvalid     = wire.BatchCheckOutcomeInvalid
	BatchCheckOutcomeForbidden   = wire.BatchCheckOutcomeForbidden
	BatchCheckOutcomeUnavailable = wire.BatchCheckOutcomeUnavailable
)

func BatchCheckOutcomeValues() []BatchCheckOutcome { return wire.BatchCheckOutcomeValues() }

type SelectorOperator struct{ transport listen.FrameClient }

func NewSelectorOperator(endpoint string) *SelectorOperator {
	return NewSelectorOperatorWithTransport(listen.FrameClient{Endpoint: endpoint})
}
func NewSelectorOperatorWithTransport(t listen.FrameClient) *SelectorOperator {
	return &SelectorOperator{transport: t.WithDefaults(5*time.Second, 1<<20)}
}
func selectorRange(cursor string, limit int64) bool {
	return len(cursor) <= 256 && limit >= 1 && limit <= 64
}
func selectionShape(s PermissionSelection) bool {
	return boundedOperatorString(s.Permission.Action, 128) && boundedOperatorString(s.Permission.ResourceProfile, 128) && (s.Selector.Kind == ResourceSelectorKindAll && s.Selector.Target == nil || s.Selector.Kind == ResourceSelectorKindOne && len(s.Selector.Target) > 0 && len(s.Selector.Target) <= 16<<10)
}
func selectorPageHeader(out PolicyPageOutcome, revision, next string, complete bool, n int, limit int64) bool {
	if out != PolicyPageOutcomePage {
		return revision == "" && next == "" && !complete && n == 0
	}
	return boundedOperatorString(revision, 128) && n >= 0 && int64(n) <= limit && len(next) <= 256 && complete == (next == "") && (complete || n > 0)
}
func (c *Client) ListPermissionDefinitionsContext(ctx context.Context, cursor string, limit int64) (PermissionDefinitionPage, error) {
	if e := ctx.Err(); e != nil {
		return PermissionDefinitionPage{}, e
	}
	if !selectorRange(cursor, limit) {
		return PermissionDefinitionPage{}, errors.New("rights: invalid definition range")
	}
	v, e := wire.NewSelectorAuthorizationClient(c.transport.WithContext(ctx)).ListPermissionDefinitions(cursor, limit)
	if e != nil {
		return v, e
	}
	if !selectorPageHeader(v.Outcome, v.Revision, v.Next, v.Complete, len(v.Definitions), limit) || len(wire.EncodePermissionDefinitionPage(&v)) > 256<<10 {
		return PermissionDefinitionPage{}, errors.New("rights: invalid definition page")
	}
	return v, nil
}
func (c *Client) ListPermissionBundlesContext(ctx context.Context, cursor string, limit int64) (PermissionBundlePage, error) {
	if e := ctx.Err(); e != nil {
		return PermissionBundlePage{}, e
	}
	if !selectorRange(cursor, limit) {
		return PermissionBundlePage{}, errors.New("rights: invalid bundle range")
	}
	v, e := wire.NewSelectorAuthorizationClient(c.transport.WithContext(ctx)).ListPermissionBundles(cursor, limit)
	if e != nil {
		return v, e
	}
	if !selectorPageHeader(v.Outcome, v.Revision, v.Next, v.Complete, len(v.Bundles), limit) || len(wire.EncodePermissionBundlePage(&v)) > 256<<10 {
		return PermissionBundlePage{}, errors.New("rights: invalid bundle page")
	}
	return v, nil
}
func checkedBatch(v BatchDecision, e error, req CheckBatchRequest) (BatchDecision, error) {
	if e != nil {
		return BatchDecision{}, e
	}
	bad := false
	switch v.Outcome {
	case BatchCheckOutcomeChecked:
		bad = !boundedOperatorString(v.Revision, 128) || len(v.Outcomes) != len(req.Resources) || (v.CollectionOutcome != nil) != (req.CollectionAdmission != nil)
		bad = bad || req.ExpectedRevision != "" && v.Revision != req.ExpectedRevision
		outcomes := append([]DecisionOutcome{}, v.Outcomes...)
		if v.CollectionOutcome != nil {
			outcomes = append(outcomes, *v.CollectionOutcome)
		}
		for _, o := range outcomes {
			if o != DecisionOutcomePermitted && o != DecisionOutcomeDenied && o != DecisionOutcomeNotGranted && o != DecisionOutcomeUnknownAction {
				bad = true
			}
		}
	case BatchCheckOutcomeConflict:
		bad = !boundedOperatorString(v.Revision, 128) || len(v.Outcomes) != 0 || v.CollectionOutcome != nil
	case BatchCheckOutcomeInvalid, BatchCheckOutcomeForbidden, BatchCheckOutcomeUnavailable:
		bad = v.Revision != "" || len(v.Outcomes) != 0 || v.CollectionOutcome != nil
	default:
		bad = true
	}
	if bad {
		return BatchDecision{}, errors.New("rights: inconsistent batch response")
	}
	return v, nil
}
func (c *Client) CheckBatchContext(ctx context.Context, req CheckBatchRequest) (BatchDecision, error) {
	if e := ctx.Err(); e != nil {
		return BatchDecision{}, e
	}
	v, e := wire.NewSelectorAuthorizationClient(c.transport.WithContext(ctx)).CheckBatch(req)
	return checkedBatch(v, e, req)
}
func (c *Client) CheckBatchForContext(ctx context.Context, subject Subject, req CheckBatchRequest) (BatchDecision, error) {
	if e := ctx.Err(); e != nil {
		return BatchDecision{}, e
	}
	v, e := wire.NewSelectorAuthorizationClient(c.transport.WithContext(ctx)).CheckBatchFor(subject, req)
	return checkedBatch(v, e, req)
}
func (c *Client) CheckLegacyOperationForContext(ctx context.Context, subject Subject, req LegacyOperationRequest) (Decision, error) {
	if e := ctx.Err(); e != nil {
		return Decision{}, e
	}
	v, e := wire.NewSelectorAuthorizationClient(c.transport.WithContext(ctx)).CheckLegacyOperationFor(subject, req)
	return checked(v, e)
}
func checkedSelectorEdit(v SelectorEdit, e error) (SelectorEdit, error) {
	if e != nil {
		return SelectorEdit{}, e
	}
	evaluated := v.Outcome == PolicyEditOutcomeApplied || v.Outcome == PolicyEditOutcomeConflict
	if evaluated != boundedOperatorString(v.Revision, 128) || !evaluated && (len(v.Current) != 0 || v.BundleOrigin != nil) || len(v.Current) > 64 {
		return SelectorEdit{}, errors.New("rights: inconsistent selector edit")
	}
	for _, r := range v.Current {
		if !validSubject(r.Rule.Subject) || !validSubject(r.SetBy) || !selectionShape(r.Rule.Selection) {
			return SelectorEdit{}, errors.New("rights: invalid selector record")
		}
	}
	return v, nil
}
func (c *SelectorOperator) ListSelectorRulesContext(ctx context.Context, cursor string, limit int64) (SelectorRulePage, error) {
	if e := ctx.Err(); e != nil {
		return SelectorRulePage{}, e
	}
	if !selectorRange(cursor, limit) {
		return SelectorRulePage{}, errors.New("rights: invalid selector range")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).ListSelectorRules(cursor, limit)
	if e != nil {
		return v, e
	}
	if !selectorPageHeader(v.Outcome, v.Revision, v.Next, v.Complete, len(v.Records), limit) || len(wire.EncodeSelectorRulePage(&v)) > 256<<10 {
		return SelectorRulePage{}, errors.New("rights: invalid selector page")
	}
	for _, r := range v.Records {
		if !validSubject(r.Rule.Subject) || !selectionShape(r.Rule.Selection) {
			return SelectorRulePage{}, errors.New("rights: invalid selector record")
		}
	}
	return v, nil
}
func (c *SelectorOperator) ReadSelectorRuleContext(ctx context.Context, subject Subject, selection PermissionSelection) (SelectorRuleRead, error) {
	if e := ctx.Err(); e != nil {
		return SelectorRuleRead{}, e
	}
	if !validSubject(subject) || !selectionShape(selection) {
		return SelectorRuleRead{}, errors.New("rights: invalid selector read")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).ReadSelectorRule(subject, selection)
	if e != nil {
		return v, e
	}
	evaluated := v.Outcome == RuleReadOutcomeFound || v.Outcome == RuleReadOutcomeExpired || v.Outcome == RuleReadOutcomeUnknown
	if evaluated != boundedOperatorString(v.Revision, 128) || (v.Record != nil) != (v.Outcome == RuleReadOutcomeFound || v.Outcome == RuleReadOutcomeExpired) {
		return SelectorRuleRead{}, errors.New("rights: inconsistent selector read")
	}
	return v, nil
}
func validSelectorDuration(ttl time.Duration) bool {
	return ttl >= 0 && ttl <= 365*24*time.Hour && ttl%time.Millisecond == 0
}
func (c *SelectorOperator) SetSelectorRuleContext(ctx context.Context, expected string, rule SelectorRule, ttl time.Duration, why string) (SelectorEdit, error) {
	if e := ctx.Err(); e != nil {
		return SelectorEdit{}, e
	}
	if !boundedOperatorString(expected, 128) || !validSubject(rule.Subject) || !selectionShape(rule.Selection) || !validSelectorDuration(ttl) {
		return SelectorEdit{}, errors.New("rights: invalid selector edit")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).SetSelectorRule(expected, rule, ttl.Milliseconds(), why)
	return checkedSelectorEdit(v, e)
}
func (c *SelectorOperator) RemoveSelectorRuleContext(ctx context.Context, expected string, subject Subject, selection PermissionSelection) (SelectorEdit, error) {
	if e := ctx.Err(); e != nil {
		return SelectorEdit{}, e
	}
	if !boundedOperatorString(expected, 128) || !validSubject(subject) || !selectionShape(selection) {
		return SelectorEdit{}, errors.New("rights: invalid selector removal")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).RemoveSelectorRule(expected, subject, selection)
	return checkedSelectorEdit(v, e)
}
func (c *SelectorOperator) ApplyBundleContext(ctx context.Context, expected string, subject Subject, ref string, selector ResourceSelector, ttl time.Duration, why string) (SelectorEdit, error) {
	if e := ctx.Err(); e != nil {
		return SelectorEdit{}, e
	}
	if !boundedOperatorString(expected, 128) || !validSubject(subject) || !boundedOperatorString(ref, 128) || !validSelectorDuration(ttl) {
		return SelectorEdit{}, errors.New("rights: invalid bundle edit")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).ApplyBundle(expected, subject, ref, selector, ttl.Milliseconds(), why)
	return checkedSelectorEdit(v, e)
}
func (c *SelectorOperator) RemoveBundleContext(ctx context.Context, expected string, subject Subject, id string) (SelectorEdit, error) {
	if e := ctx.Err(); e != nil {
		return SelectorEdit{}, e
	}
	if !boundedOperatorString(expected, 128) || !validSubject(subject) || !boundedOperatorString(id, 128) {
		return SelectorEdit{}, errors.New("rights: invalid bundle removal")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).RemoveBundle(expected, subject, id)
	return checkedSelectorEdit(v, e)
}
func (c *SelectorOperator) ApplyPermissionAllowContext(ctx context.Context, expected, id string) (SelectorEdit, error) {
	if e := ctx.Err(); e != nil {
		return SelectorEdit{}, e
	}
	if !boundedOperatorString(expected, 128) || !boundedOperatorString(id, 128) {
		return SelectorEdit{}, errors.New("rights: invalid permission effect")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).ApplyPermissionAllow(expected, id)
	return checkedSelectorEdit(v, e)
}
func (c *SelectorOperator) UndoPermissionEffectContext(ctx context.Context, expected, id string) (SelectorEdit, error) {
	if e := ctx.Err(); e != nil {
		return SelectorEdit{}, e
	}
	if !boundedOperatorString(expected, 128) || !boundedOperatorString(id, 128) {
		return SelectorEdit{}, errors.New("rights: invalid permission undo")
	}
	v, e := wire.NewSelectorAuthorizationOperatorClient(c.transport.WithContext(ctx)).UndoPermissionEffect(expected, id)
	return checkedSelectorEdit(v, e)
}
