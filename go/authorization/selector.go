package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/openabstractions/abstraction-identity"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// AuthorizeSelectorEnforcer trusts this native receiving peer to assert the
// actual subject and captured target for this exact registered permission.
// The callback validates owner/operation admission; Rights owns all matching.
// It must honor ctx and never enter a resource-owner lock held by its caller.
type AuthorizeSelectorEnforcer func(context.Context, *identity.Peer, wire.PermissionSelection) bool

func (h *Host) EnableSelectorEnforcer(authorize AuthorizeSelectorEnforcer) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.serving || h.ctx.Err() != nil || authorize == nil || h.policy.Definitions == nil || !h.policy.Definitions.HasSelectors() {
		return errors.New("rights: configure typed enforcer and definitions before Serve")
	}
	h.selectorEnforcer = authorize
	return nil
}
func (h *Host) SelectorAvailable() bool {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	return h.ctx.Err() == nil && h.policy.Definitions != nil && h.policy.Definitions.HasSelectors()
}
func (h *Host) SelectorOperatorAvailable() bool {
	return h.SelectorAvailable() && h.OperatorAvailable()
}

type selectorReceiver struct{ receiver }
type selectorOperatorReceiver struct{ operatorReceiver }

func batchRefusal(o wire.BatchCheckOutcome) wire.BatchDecision {
	return wire.BatchDecision{Outcome: o, Outcomes: []wire.DecisionOutcome{}}
}
func (r *selectorReceiver) CheckBatch(request wire.CheckBatchRequest) (wire.BatchDecision, error) {
	subject, _, err := r.caller()
	if err != nil || subject.Account != r.host.owner {
		return batchRefusal(wire.BatchCheckOutcomeForbidden), nil
	}
	if !r.host.SelectorAvailable() {
		return batchRefusal(wire.BatchCheckOutcomeUnavailable), nil
	}
	if len(request.Resources) > rights.MaxBatchResources {
		return batchRefusal(wire.BatchCheckOutcomeInvalid), nil
	}
	// A direct app supplies requested owner documents, never captured evidence.
	resources := make([]wire.ConcreteResource, len(request.Resources))
	for i, target := range request.Resources {
		selection, err := r.host.policy.Definitions.PrepareSelection(wire.PermissionSelection{Permission: target.Permission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: target.Target}})
		if err != nil {
			if errors.Is(err, rights.ErrPermissionUnavailable) {
				return batchRefusal(wire.BatchCheckOutcomeUnavailable), nil
			}
			return batchRefusal(wire.BatchCheckOutcomeInvalid), nil
		}
		resources[i] = wire.ConcreteResource{Permission: selection.Permission, Target: selection.Selector.Target}
	}
	request.Resources = resources
	if err := r.call.Recheck(); err != nil {
		return batchRefusal(wire.BatchCheckOutcomeForbidden), nil
	}
	return r.host.policy.CheckBatchContext(r.ctx, subject, request), nil
}
func (r *selectorReceiver) CheckBatchFor(subject wire.Subject, request wire.CheckBatchRequest) (wire.BatchDecision, error) {
	caller, peer, err := r.caller()
	if err != nil || caller.Account != r.host.owner || subject.Account != r.host.owner || r.host.selectorEnforcer == nil {
		return batchRefusal(wire.BatchCheckOutcomeForbidden), nil
	}
	if len(request.Resources) > rights.MaxBatchResources {
		return batchRefusal(wire.BatchCheckOutcomeInvalid), nil
	}
	if !r.host.SelectorAvailable() {
		return batchRefusal(wire.BatchCheckOutcomeUnavailable), nil
	}
	if request.CollectionAdmission != nil && !r.host.selectorEnforcer(r.ctx, peer, wire.PermissionSelection{Permission: *request.CollectionAdmission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindAll}}) {
		return batchRefusal(wire.BatchCheckOutcomeForbidden), nil
	}
	for _, target := range request.Resources {
		if len(target.Target) > rights.MaxTargetBytes {
			return batchRefusal(wire.BatchCheckOutcomeInvalid), nil
		}
		if !r.host.selectorEnforcer(r.ctx, peer, wire.PermissionSelection{Permission: target.Permission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: target.Target}}) {
			return batchRefusal(wire.BatchCheckOutcomeForbidden), nil
		}
	}
	if err := r.ctx.Err(); err != nil {
		return wire.BatchDecision{}, err
	}
	if err := r.call.Recheck(); err != nil {
		return batchRefusal(wire.BatchCheckOutcomeForbidden), nil
	}
	return r.host.policy.CheckBatchContext(r.ctx, subject, request), nil
}
func (r *selectorReceiver) CheckLegacyOperationFor(subject wire.Subject, request wire.LegacyOperationRequest) (wire.Decision, error) {
	caller, peer, err := r.caller()
	if err != nil || caller.Account != r.host.owner || subject.Account != r.host.owner || r.host.enforcer == nil || !r.host.enforcer(r.ctx, peer, request.LegacyAction, request.LegacyResource) {
		return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
	}
	if target := request.ConcreteOperation; target != nil {
		if r.host.selectorEnforcer == nil || !r.host.selectorEnforcer(r.ctx, peer, wire.PermissionSelection{Permission: target.Permission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: target.Target}}) {
			return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
		}
	}
	if err := r.ctx.Err(); err != nil {
		return wire.Decision{}, err
	}
	if err := r.call.Recheck(); err != nil {
		return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
	}
	return r.host.policy.CheckLegacyOperationContext(r.ctx, subject, request), nil
}

// A cursor binds one native subject, host epoch, page kind and shared revision.
func (r *receiver) selectorOffset(subject wire.Subject, kind, revision, cursor string, limit int64, total int) (int, string, wire.PolicyPageOutcome) {
	if limit < 1 || limit > 64 || len(cursor) > 256 || !utf8.ValidString(cursor) {
		return 0, "", wire.PolicyPageOutcomeInvalid
	}
	data, _ := json.Marshal(subject)
	sum := sha256.Sum256(data)
	prefix := kind + ":" + r.host.operatorEpoch + ":" + hex.EncodeToString(sum[:]) + ":" + revision + ":"
	if cursor == "" {
		return 0, prefix, wire.PolicyPageOutcomePage
	}
	word, ok := strings.CutPrefix(cursor, prefix)
	n, err := strconv.Atoi(word)
	if !ok || err != nil || n < 0 || n > total || strconv.Itoa(n) != word {
		return 0, "", wire.PolicyPageOutcomeGap
	}
	return n, prefix, wire.PolicyPageOutcomePage
}
func (r *selectorReceiver) ListPermissionDefinitions(cursor string, limit int64) (wire.PermissionDefinitionPage, error) {
	refuse := func(out wire.PolicyPageOutcome) wire.PermissionDefinitionPage {
		return wire.PermissionDefinitionPage{Outcome: out, Definitions: []wire.SelectorPermissionDefinition{}}
	}
	subject, _, err := r.caller()
	if err != nil || subject.Account != r.host.owner {
		return refuse(wire.PolicyPageOutcomeForbidden), nil
	}
	if !r.host.SelectorAvailable() {
		return refuse(wire.PolicyPageOutcomeUnavailable), nil
	}
	revision, definitions, _, err := r.host.policy.DefinitionSnapshotContext(r.ctx)
	if err != nil {
		return refuse(wire.PolicyPageOutcomeUnavailable), nil
	}
	offset, prefix, outcome := r.selectorOffset(subject, "definitions", revision, cursor, limit, len(definitions))
	if outcome != wire.PolicyPageOutcomePage {
		return refuse(outcome), nil
	}
	page := wire.PermissionDefinitionPage{Outcome: outcome, Revision: revision, Definitions: []wire.SelectorPermissionDefinition{}}
	for offset < len(definitions) && int64(len(page.Definitions)) < limit {
		page.Definitions = append(page.Definitions, definitions[offset])
		if len(wire.EncodePermissionDefinitionPage(&page)) > (256<<10)-512 {
			page.Definitions = page.Definitions[:len(page.Definitions)-1]
			if len(page.Definitions) == 0 {
				return refuse(wire.PolicyPageOutcomeUnavailable), nil
			}
			break
		}
		offset++
	}
	page.Complete = offset == len(definitions)
	if !page.Complete {
		page.Next = prefix + strconv.Itoa(offset)
	}
	if err := r.call.Recheck(); err != nil {
		return refuse(wire.PolicyPageOutcomeForbidden), nil
	}
	return page, nil
}
func (r *selectorReceiver) ListPermissionBundles(cursor string, limit int64) (wire.PermissionBundlePage, error) {
	refuse := func(out wire.PolicyPageOutcome) wire.PermissionBundlePage {
		return wire.PermissionBundlePage{Outcome: out, Bundles: []wire.PermissionBundleDefinition{}}
	}
	subject, _, err := r.caller()
	if err != nil || subject.Account != r.host.owner {
		return refuse(wire.PolicyPageOutcomeForbidden), nil
	}
	if !r.host.SelectorAvailable() {
		return refuse(wire.PolicyPageOutcomeUnavailable), nil
	}
	revision, _, bundles, err := r.host.policy.DefinitionSnapshotContext(r.ctx)
	if err != nil {
		return refuse(wire.PolicyPageOutcomeUnavailable), nil
	}
	offset, prefix, outcome := r.selectorOffset(subject, "bundles", revision, cursor, limit, len(bundles))
	if outcome != wire.PolicyPageOutcomePage {
		return refuse(outcome), nil
	}
	page := wire.PermissionBundlePage{Outcome: outcome, Revision: revision, Bundles: []wire.PermissionBundleDefinition{}}
	for offset < len(bundles) && int64(len(page.Bundles)) < limit {
		page.Bundles = append(page.Bundles, bundles[offset])
		if len(wire.EncodePermissionBundlePage(&page)) > (256<<10)-512 {
			page.Bundles = page.Bundles[:len(page.Bundles)-1]
			if len(page.Bundles) == 0 {
				return refuse(wire.PolicyPageOutcomeUnavailable), nil
			}
			break
		}
		offset++
	}
	page.Complete = offset == len(bundles)
	if !page.Complete {
		page.Next = prefix + strconv.Itoa(offset)
	}
	if err := r.call.Recheck(); err != nil {
		return refuse(wire.PolicyPageOutcomeForbidden), nil
	}
	return page, nil
}
func (r *selectorOperatorReceiver) ListSelectorRules(cursor string, limit int64) (wire.SelectorRulePage, error) {
	refuse := func(out wire.PolicyPageOutcome) wire.SelectorRulePage {
		return wire.SelectorRulePage{Outcome: out, Records: []wire.SelectorRuleRecord{}}
	}
	subject, err := r.authorize()
	if err != nil {
		return refuse(operatorPageError(err)), nil
	}
	if !r.host.SelectorAvailable() {
		return refuse(wire.PolicyPageOutcomeUnavailable), nil
	}
	revision, records, err := r.host.policy.SelectorSnapshotContext(r.ctx)
	if err != nil {
		return refuse(wire.PolicyPageOutcomeUnavailable), nil
	}
	offset, prefix, outcome := r.selectorOffset(subject, "selectors", revision, cursor, limit, len(records))
	if outcome != wire.PolicyPageOutcomePage {
		return refuse(outcome), nil
	}
	page := wire.SelectorRulePage{Outcome: outcome, Revision: revision, Records: []wire.SelectorRuleRecord{}}
	for offset < len(records) && int64(len(page.Records)) < limit {
		page.Records = append(page.Records, records[offset])
		if len(wire.EncodeSelectorRulePage(&page)) > (256<<10)-512 {
			page.Records = page.Records[:len(page.Records)-1]
			if len(page.Records) == 0 {
				return refuse(wire.PolicyPageOutcomeUnavailable), nil
			}
			break
		}
		offset++
	}
	page.Complete = offset == len(records)
	if !page.Complete {
		page.Next = prefix + strconv.Itoa(offset)
	}
	if _, err := r.authorize(); err != nil {
		return refuse(operatorPageError(err)), nil
	}
	return page, nil
}
func (r *selectorOperatorReceiver) ReadSelectorRule(subject wire.Subject, selection wire.PermissionSelection) (wire.SelectorRuleRead, error) {
	if _, err := r.authorize(); err != nil {
		return wire.SelectorRuleRead{Outcome: operatorRuleError(err)}, nil
	}
	if subject.Account != r.host.owner {
		return wire.SelectorRuleRead{Outcome: wire.RuleReadOutcomeForbidden}, nil
	}
	result := r.host.policy.ReadSelectorRuleContext(r.ctx, subject, selection)
	if _, err := r.authorize(); err != nil {
		return wire.SelectorRuleRead{Outcome: operatorRuleError(err)}, nil
	}
	if len(wire.EncodeSelectorRuleRead(&result)) > 256<<10 {
		return wire.SelectorRuleRead{Outcome: wire.RuleReadOutcomeUnavailable}, nil
	}
	return result, nil
}
func selectorEditRefusal(out wire.PolicyEditOutcome) wire.SelectorEdit {
	return wire.SelectorEdit{Outcome: out, Current: []wire.SelectorRuleRecord{}}
}
func (r *selectorOperatorReceiver) edit(subject wire.Subject, run func(wire.Subject, func() error) (wire.SelectorEdit, error)) (wire.SelectorEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return selectorEditRefusal(operatorPolicyError(err)), nil
	}
	if subject.Account != r.host.owner {
		return selectorEditRefusal(wire.PolicyEditOutcomeForbidden), nil
	}
	if !r.host.SelectorAvailable() {
		return selectorEditRefusal(wire.PolicyEditOutcomeUnavailable), nil
	}
	result, err := run(by, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return selectorEditRefusal(operatorPolicyError(err)), nil
	}
	return result, nil
}
func selectorTTL(ms int64) time.Duration {
	if ms < 0 || ms > rights.MaxRuleTTL.Milliseconds() {
		return -1
	}
	return time.Duration(ms) * time.Millisecond
}
func (r *selectorOperatorReceiver) SetSelectorRule(expected string, rule wire.SelectorRule, ttlMS int64, why string) (wire.SelectorEdit, error) {
	return r.edit(rule.Subject, func(by wire.Subject, authorize func() error) (wire.SelectorEdit, error) {
		return r.host.policy.SetSelectorRuleContext(r.ctx, expected, rule, rights.RuleEdit{By: by, TTL: selectorTTL(ttlMS), Why: why}, authorize)
	})
}
func (r *selectorOperatorReceiver) RemoveSelectorRule(expected string, subject wire.Subject, selection wire.PermissionSelection) (wire.SelectorEdit, error) {
	return r.edit(subject, func(by wire.Subject, authorize func() error) (wire.SelectorEdit, error) {
		return r.host.policy.RemoveSelectorRuleContext(r.ctx, expected, subject, selection, rights.RuleEdit{By: by}, authorize)
	})
}
func (r *selectorOperatorReceiver) ApplyBundle(expected string, subject wire.Subject, ref string, selector wire.ResourceSelector, ttlMS int64, why string) (wire.SelectorEdit, error) {
	return r.edit(subject, func(by wire.Subject, authorize func() error) (wire.SelectorEdit, error) {
		return r.host.policy.ApplyBundleContext(r.ctx, expected, subject, ref, selector, rights.RuleEdit{By: by, TTL: selectorTTL(ttlMS), Why: why}, authorize)
	})
}
func (r *selectorOperatorReceiver) RemoveBundle(expected string, subject wire.Subject, id string) (wire.SelectorEdit, error) {
	return r.edit(subject, func(by wire.Subject, authorize func() error) (wire.SelectorEdit, error) {
		return r.host.policy.RemoveBundleContext(r.ctx, expected, subject, id, rights.RuleEdit{By: by}, authorize)
	})
}
func (r *selectorOperatorReceiver) permissionEffect(expected, id string, undo bool) (wire.SelectorEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return selectorEditRefusal(operatorPolicyError(err)), nil
	}
	valid := func(s string) bool {
		return len(s) > 0 && len(s) <= 128 && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
	}
	if !valid(expected) || !valid(id) {
		return selectorEditRefusal(wire.PolicyEditOutcomeInvalid), nil
	}
	var result wire.SelectorEdit
	if undo {
		if r.host.permissionUndo == nil {
			return selectorEditRefusal(wire.PolicyEditOutcomeUnavailable), nil
		}
		result, err = r.host.permissionUndo(r.ctx, by, expected, id, func() error { _, err := r.authorize(); return err })
	} else {
		if r.host.permissionAllow == nil {
			return selectorEditRefusal(wire.PolicyEditOutcomeUnavailable), nil
		}
		result, err = r.host.permissionAllow(r.ctx, by, expected, id, func() error { _, err := r.authorize(); return err })
	}
	if err != nil {
		return selectorEditRefusal(operatorPolicyError(err)), nil
	}
	return result, nil
}
func (r *selectorOperatorReceiver) ApplyPermissionAllow(expected, id string) (wire.SelectorEdit, error) {
	return r.permissionEffect(expected, id, false)
}
func (r *selectorOperatorReceiver) UndoPermissionEffect(expected, id string) (wire.SelectorEdit, error) {
	return r.permissionEffect(expected, id, true)
}
