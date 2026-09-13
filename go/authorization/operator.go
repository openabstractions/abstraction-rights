package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AuthorizeOperator must honor ctx and be safe for concurrent calls. It receives
// native rechecked evidence; policy subjects in requests are administrative
// targets. Return ErrOperatorForbidden for denial, other errors for outage.
type AuthorizeOperator func(context.Context, *identity.Peer) error

var ErrOperatorForbidden = errors.New("rights: operator forbidden")

func operatorError(err error) string {
	if errors.Is(err, ErrOperatorForbidden) {
		return "forbidden"
	}
	return "unavailable"
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
func (h *Host) OperatorAvailable() bool {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	return h.operator != nil && h.ctx.Err() == nil
}

type operatorReceiver struct{ receiver }

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
func policyPageRefusal(outcome string) wire.PolicyPage {
	return wire.PolicyPage{Outcome: outcome, Catalog: []string{}, Rules: []wire.PolicyRule{}}
}
func (r *operatorReceiver) ListPolicy(cursor string, limit int64) (wire.PolicyPage, error) {
	subject, err := r.authorize()
	if err != nil {
		return policyPageRefusal(operatorError(err)), nil
	}
	if limit < 1 || limit > 64 || len(cursor) > 256 || !utf8.ValidString(cursor) {
		return policyPageRefusal("invalid"), nil
	}
	snapshot, err := r.host.policy.OperatorSnapshot()
	if err != nil {
		return policyPageRefusal("unavailable"), nil
	}
	scope, _ := json.Marshal(subject)
	sum := sha256.Sum256(scope)
	prefix := r.host.operatorEpoch + ":" + hex.EncodeToString(sum[:]) + ":" + snapshot.Revision + ":"
	offset := 0
	if cursor != "" {
		word, ok := strings.CutPrefix(cursor, prefix)
		n, e := strconv.Atoi(word)
		if !ok || e != nil || n < 0 || n > len(snapshot.Rules) || strconv.Itoa(n) != word {
			return policyPageRefusal("gap"), nil
		}
		offset = n
	}
	catalog, err := json.Marshal(snapshot.Catalog)
	if err != nil {
		return policyPageRefusal("unavailable"), nil
	}
	used := 2048 + len(catalog) + 32*len(snapshot.Catalog)
	if used > 256<<10 {
		return policyPageRefusal("unavailable"), nil
	}
	page := wire.PolicyPage{Outcome: "page", Revision: snapshot.Revision, Catalog: snapshot.Catalog, Rules: []wire.PolicyRule{}}
	for offset < len(snapshot.Rules) && int64(len(page.Rules)) < limit {
		rule := snapshot.Rules[offset]
		data, e := json.Marshal(rule)
		cost := len(data) + 1024
		if e != nil || cost > (256<<10)-used && len(page.Rules) == 0 {
			return policyPageRefusal("unavailable"), nil
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
		return policyPageRefusal(operatorError(err)), nil
	}
	return page, nil
}
func (r *operatorReceiver) SetRule(expected string, rule wire.PolicyRule) (wire.PolicyEdit, error) {
	return r.edit(expected, rule.Subject, rule.Action, rule.Resource, &rule.Permit)
}
func (r *operatorReceiver) RevokeRule(expected string, subject wire.Subject, action, resource string) (wire.PolicyEdit, error) {
	return r.edit(expected, subject, action, resource, nil)
}
func (r *operatorReceiver) edit(expected string, subject wire.Subject, action, resource string, permit *bool) (wire.PolicyEdit, error) {
	if _, err := r.authorize(); err != nil {
		return wire.PolicyEdit{Outcome: operatorError(err)}, nil
	}
	result, err := r.host.policy.EditRule(expected, subject, action, resource, permit, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.PolicyEdit{Outcome: operatorError(err)}, nil
	}
	return result, nil
}
