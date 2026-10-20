package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// AuthorizeOperator must honor ctx and be safe for concurrent calls. It receives
// native rechecked evidence; policy subjects in requests are administrative
// targets. Return ErrOperatorForbidden for denial, other errors for outage.
type AuthorizeOperator func(context.Context, *identity.Peer) error

// ApplyFirstUseAllow is trusted runtime composition. It pins the actual Book
// occurrence before entering rights, derives its complete target permits and
// commits their durable proof. It must honor ctx and recheck authorize in-lock.
type ApplyFirstUseAllow func(ctx context.Context, operator wire.Subject, expected, id string, authorize func() error) (wire.PolicyEdit, error)

func (h *Host) EnableFirstUseAllow(apply ApplyFirstUseAllow) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.serving || h.ctx.Err() != nil || apply == nil {
		return errors.New("rights: configure first-use Allow before Serve")
	}
	h.firstUseAllow = apply
	return nil
}

var ErrOperatorForbidden = errors.New("rights: operator forbidden")

func operatorPageError(err error) wire.PolicyPageOutcome {
	if errors.Is(err, ErrOperatorForbidden) {
		return wire.PolicyPageOutcomeForbidden
	}
	return wire.PolicyPageOutcomeUnavailable
}
func operatorPolicyError(err error) wire.PolicyEditOutcome {
	if errors.Is(err, ErrOperatorForbidden) {
		return wire.PolicyEditOutcomeForbidden
	}
	if errors.Is(err, rights.ErrUnresolvedShortName) {
		return wire.PolicyEditOutcomeInvalid
	}
	return wire.PolicyEditOutcomeUnavailable
}
func operatorRuleError(err error) wire.RuleReadOutcome {
	if errors.Is(err, ErrOperatorForbidden) {
		return wire.RuleReadOutcomeForbidden
	}
	return wire.RuleReadOutcomeUnavailable
}
func operatorDecisionError(err error) wire.DecisionOutcome {
	if errors.Is(err, ErrOperatorForbidden) {
		return wire.DecisionOutcomeForbidden
	}
	return wire.DecisionOutcomeUnavailable
}
func operatorActionError(err error) wire.ActionEditOutcome {
	if errors.Is(err, ErrOperatorForbidden) {
		return wire.ActionEditOutcomeForbidden
	}
	return wire.ActionEditOutcomeUnavailable
}
func (h *Host) EnableOperator(authorize AuthorizeOperator) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.serving || h.ctx.Err() != nil {
		return errors.New("rights: configure operator before Serve")
	}
	if authorize == nil {
		return errors.New("rights: operator authorization required")
	}
	h.operator = authorize
	return nil
}

// Available reports whether the host has not been closed.
func (h *Host) Available() bool {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	return h.ctx.Err() == nil
}

func (h *Host) OperatorAvailable() bool {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	return h.operator != nil && h.ctx.Err() == nil
}

type operatorReceiver struct{ receiver }

func (r *operatorReceiver) ApplyFirstUseAllow(expected, id string) (wire.PolicyEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	valid := func(value string) bool {
		return len(value) > 0 && len(value) <= 128 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
	}
	if !valid(expected) || !valid(id) {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if r.host.firstUseAllow == nil {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, nil
	}
	result, err := r.host.firstUseAllow(r.ctx, by, expected, id, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	return result, nil
}

func (r *operatorReceiver) authorize() (wire.Subject, error) {
	if err := r.ctx.Err(); err != nil {
		return wire.Subject{}, err
	}
	subject, peer, err := r.caller()
	if err != nil || subject.Account != r.host.owner || r.host.operator == nil {
		return wire.Subject{}, ErrOperatorForbidden
	}
	if err = r.host.operator(r.ctx, peer); err != nil {
		return wire.Subject{}, err
	}
	return subject, r.ctx.Err()
}
func policyPageRefusal(outcome wire.PolicyPageOutcome) wire.PolicyPage {
	return wire.PolicyPage{Outcome: outcome, Catalog: []string{}, Rules: []wire.PolicyRule{}}
}
func (r *operatorReceiver) ListPolicy(cursor string, limit int64) (wire.PolicyPage, error) {
	subject, err := r.authorize()
	if err != nil {
		return policyPageRefusal(operatorPageError(err)), nil
	}
	if limit < 1 || limit > 64 || len(cursor) > 256 || !utf8.ValidString(cursor) {
		return policyPageRefusal(wire.PolicyPageOutcomeInvalid), nil
	}
	snapshot, err := r.host.policy.OperatorSnapshot()
	if err != nil {
		return policyPageRefusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	scope, _ := json.Marshal(subject)
	sum := sha256.Sum256(scope)
	prefix := r.host.operatorEpoch + ":" + hex.EncodeToString(sum[:]) + ":" + snapshot.Revision + ":"
	offset := 0
	if cursor != "" {
		word, ok := strings.CutPrefix(cursor, prefix)
		n, e := strconv.Atoi(word)
		if !ok || e != nil || n < 0 || n > len(snapshot.Rules) || strconv.Itoa(n) != word {
			return policyPageRefusal(wire.PolicyPageOutcomeGap), nil
		}
		offset = n
	}
	catalog, err := json.Marshal(snapshot.Catalog)
	if err != nil {
		return policyPageRefusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	used := 2048 + len(catalog) + 32*len(snapshot.Catalog)
	if used > 256<<10 {
		return policyPageRefusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	page := wire.PolicyPage{Outcome: wire.PolicyPageOutcomePage, Revision: snapshot.Revision, Catalog: snapshot.Catalog, Rules: []wire.PolicyRule{}}
	for offset < len(snapshot.Rules) && int64(len(page.Rules)) < limit {
		rule := snapshot.Rules[offset]
		data, e := json.Marshal(rule)
		cost := len(data) + 1024
		if e != nil || cost > (256<<10)-used && len(page.Rules) == 0 {
			return policyPageRefusal(wire.PolicyPageOutcomeUnavailable), nil
		}
		if used+cost > 256<<10 {
			break
		}
		used += cost
		page.Rules = append(page.Rules, rule)
		offset++
	}
	page.Complete = offset == len(snapshot.Rules)
	if !page.Complete {
		page.Next = prefix + strconv.Itoa(offset)
	}
	if _, err = r.authorize(); err != nil {
		return policyPageRefusal(operatorPageError(err)), nil
	}
	return page, nil
}
func (r *operatorReceiver) SetRule(expected string, rule wire.PolicyRule) (wire.PolicyEdit, error) {
	return r.edit(expected, rule.Subject, rule.Action, rule.Resource, rights.RuleEdit{Permit: &rule.Permit})
}
func (r *operatorReceiver) RevokeRule(expected string, subject wire.Subject, action, resource string) (wire.PolicyEdit, error) {
	return r.edit(expected, subject, action, resource, rights.RuleEdit{})
}
func (r *operatorReceiver) StopAnswerer(expected string, answerer wire.Subject, alsoRevokeGrants bool) (wire.PolicyEdit, error) {
	if _, err := r.authorize(); err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	result, err := r.host.policy.StopAnswerer(expected, answerer, alsoRevokeGrants, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	return result, nil
}
func (r *operatorReceiver) RevokeAnswerPermits(expected string, answerer, target wire.Subject, actions []string, resource, questionID string) (wire.PolicyEdit, error) {
	if _, err := r.authorize(); err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	result, err := r.host.policy.RevokeAnswerPermits(expected, answerer, target, actions, resource, questionID, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	return result, nil
}
func (r *operatorReceiver) SetRuleFor(expected string, rule wire.PolicyRule, ttlMS int64, why string) (wire.PolicyEdit, error) {
	ttl := time.Duration(ttlMS) * time.Millisecond
	if ttlMS < 0 || ttlMS > rights.MaxRuleTTL.Milliseconds() {
		ttl = -1
	}
	return r.edit(expected, rule.Subject, rule.Action, rule.Resource, rights.RuleEdit{Permit: &rule.Permit, TTL: ttl, Why: why, Exact: true})
}
func (r *operatorReceiver) SetRulesFor(expected string, rules []wire.PolicyRule, ttlMS int64, why string) (wire.PolicyEdit, error) {
	if len(rules) < 1 || len(rules) > 2 {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	ttl := time.Duration(ttlMS) * time.Millisecond
	if ttlMS < 0 || ttlMS > rights.MaxRuleTTL.Milliseconds() {
		ttl = -1
	}
	by, err := r.authorize()
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	permit := rules[0].Permit
	result, err := r.host.policy.ChangeRules(expected, rules, rights.RuleEdit{Permit: &permit, By: by, TTL: ttl, Why: why, Exact: true}, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	return result, nil
}

// edit records the operator subject established for this call as the rule's
// provenance and rechecks authority inside the atomic edit.
func (r *operatorReceiver) edit(expected string, subject wire.Subject, action, resource string, edit rights.RuleEdit) (wire.PolicyEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	edit.By = by
	result, err := r.host.policy.ChangeRule(expected, subject, action, resource, edit, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorPolicyError(err)}, nil
	}
	return result, nil
}
func (r *operatorReceiver) ReadRule(subject wire.Subject, action, resource string) (wire.RuleRead, error) {
	if _, err := r.authorize(); err != nil {
		return wire.RuleRead{Outcome: operatorRuleError(err)}, nil
	}
	result := r.host.policy.ReadRule(subject, action, resource)
	if _, err := r.authorize(); err != nil {
		return wire.RuleRead{Outcome: operatorRuleError(err)}, nil
	}
	return result, nil
}

// ExplainFor reports one exact decision for subject with the step that
// decided it, under operator authorization rechecked before returning
// (RIGHTS-O14). Refusals carry no revision, source or name.
func (r *operatorReceiver) ExplainFor(subject wire.Subject, action, resource string) (wire.DecisionExplanation, error) {
	refusal := func(err error) wire.DecisionExplanation {
		return wire.DecisionExplanation{Outcome: operatorDecisionError(err)}
	}
	if _, err := r.authorize(); err != nil {
		return refusal(err), nil
	}
	result := r.host.policy.ExplainForContext(r.ctx, subject, action, resource)
	if _, err := r.authorize(); err != nil {
		return refusal(err), nil
	}
	return result, nil
}

// ListDefaults reads every configured account-wide default under operator
// authorization, rechecked before returning (RIGHTS-O13).
func (r *operatorReceiver) ListDefaults() (wire.DefaultPage, error) {
	refusal := func(outcome wire.PolicyPageOutcome) wire.DefaultPage {
		return wire.DefaultPage{Outcome: outcome, Defaults: []wire.AccountDefault{}}
	}
	if _, err := r.authorize(); err != nil {
		return refusal(operatorPageError(err)), nil
	}
	revision, defaults, err := r.host.policy.DefaultsSnapshot(r.ctx)
	if err != nil {
		return refusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	if _, err := r.authorize(); err != nil {
		return refusal(operatorPageError(err)), nil
	}
	return wire.DefaultPage{Outcome: wire.PolicyPageOutcomePage, Revision: revision, Defaults: defaults}, nil
}

// SetDefault turns one configured default on or off, recording the operator
// subject established for this call (RIGHTS-O13).
func (r *operatorReceiver) SetDefault(expected, name string, on bool) (wire.DefaultEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return wire.DefaultEdit{Outcome: operatorPolicyError(err)}, nil
	}
	result, err := r.host.policy.SetDefault(expected, name, on, by, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.DefaultEdit{Outcome: operatorPolicyError(err)}, nil
	}
	return result, nil
}

func (r *operatorReceiver) RegisterAction(expected, action string) (wire.ActionEdit, error) {
	return r.editAction(expected, action, true)
}
func (r *operatorReceiver) RetireAction(expected, action string) (wire.ActionEdit, error) {
	return r.editAction(expected, action, false)
}
func (r *operatorReceiver) editAction(expected, action string, register bool) (wire.ActionEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return wire.ActionEdit{Outcome: operatorActionError(err)}, nil
	}
	result, err := r.host.policy.EditAction(expected, action, register, by, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.ActionEdit{Outcome: operatorActionError(err)}, nil
	}
	return result, nil
}
