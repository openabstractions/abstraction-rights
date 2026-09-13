package client

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type PolicyRule = wire.PolicyRule
type Operator struct{ transport listen.FrameClient }

func NewOperator(endpoint string) *Operator {
	return NewOperatorWithTransport(listen.FrameClient{Endpoint: endpoint})
}

// NewOperatorWithTransport retains the caller's endpoint, server trust and waiting limits.
func NewOperatorWithTransport(transport listen.FrameClient) *Operator {
	return &Operator{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}
func boundedOperatorString(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func validPolicyRule(r PolicyRule) bool {
	return boundedOperatorString(r.Subject.Account, 128) && boundedOperatorString(r.Subject.Program, 4096) && filepath.IsAbs(r.Subject.Program) && filepath.Clean(r.Subject.Program) == r.Subject.Program && boundedOperatorString(r.Action, 128) && boundedOperatorString(r.Resource, 1024)
}
func (c *Operator) ListPolicyContext(ctx context.Context, cursor string, limit int64) (wire.PolicyPage, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyPage{}, err
	}
	if len(cursor) > 256 || !utf8.ValidString(cursor) || limit < 1 || limit > 64 {
		return wire.PolicyPage{}, errors.New("rights: invalid policy range")
	}
	page, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ListPolicy(cursor, limit)
	if err != nil {
		return wire.PolicyPage{}, err
	}
	if page.Outcome != "page" {
		if page.Revision != "" || len(page.Catalog) != 0 || len(page.Rules) != 0 || page.Next != "" || page.Complete {
			return wire.PolicyPage{}, errors.New("rights: malformed policy refusal")
		}
		return page, nil
	}
	if !boundedOperatorString(page.Revision, 128) || len(page.Catalog) < 1 || len(page.Catalog) > 64 || int64(len(page.Rules)) > limit || len(page.Next) > 256 || page.Complete != (page.Next == "") || (!page.Complete && (len(page.Rules) == 0 || page.Next == cursor)) {
		return wire.PolicyPage{}, errors.New("rights: malformed policy page")
	}
	for i, a := range page.Catalog {
		if !boundedOperatorString(a, 128) || (i > 0 && page.Catalog[i-1] >= a) {
			return wire.PolicyPage{}, errors.New("rights: invalid catalogue")
		}
	}
	data, _ := json.Marshal(page.Catalog)
	used := 2048 + len(data) + 32*len(page.Catalog)
	keys := map[string]bool{}
	for _, rule := range page.Rules {
		key := rule.Subject.Account + "\x00" + rule.Subject.Program + "\x00" + rule.Action + "\x00" + rule.Resource
		if !validPolicyRule(rule) || !slices.Contains(page.Catalog, rule.Action) || keys[key] {
			return wire.PolicyPage{}, errors.New("rights: invalid policy rule")
		}
		keys[key] = true
		data, _ := json.Marshal(rule)
		used += len(data) + 1024
	}
	if used > 256<<10 {
		return wire.PolicyPage{}, errors.New("rights: oversized policy page")
	}
	return page, nil
}
func (c *Operator) SetRuleContext(ctx context.Context, expected string, rule PolicyRule) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	rule.Subject.Program = filepath.Clean(rule.Subject.Program)
	if !boundedOperatorString(expected, 128) || !validPolicyRule(rule) {
		return wire.PolicyEdit{}, errors.New("rights: invalid policy edit")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).SetRule(expected, rule)
	return checkedPolicyEdit(result, err, rule.Subject, rule.Action, rule.Resource, &rule.Permit)
}
func (c *Operator) RevokeRuleContext(ctx context.Context, expected string, subject Subject, action, resource string) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	subject.Program = filepath.Clean(subject.Program)
	if !boundedOperatorString(expected, 128) || !validPolicyRule(PolicyRule{Subject: subject, Action: action, Resource: resource}) {
		return wire.PolicyEdit{}, errors.New("rights: invalid policy revoke")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RevokeRule(expected, subject, action, resource)
	return checkedPolicyEdit(result, err, subject, action, resource, nil)
}

// A lost reply is uncertain. Clients never retry or substitute a fresh revision.
func checkedPolicyEdit(result wire.PolicyEdit, err error, subject Subject, action, resource string, permit *bool) (wire.PolicyEdit, error) {
	if err != nil {
		return wire.PolicyEdit{}, err
	}
	observed := result.Outcome == "applied" || result.Outcome == "conflict"
	if observed != boundedOperatorString(result.Revision, 128) || (!observed && (result.Revision != "" || result.Current != nil)) {
		return wire.PolicyEdit{}, errors.New("rights: malformed edit revision")
	}
	if r := result.Current; r != nil {
		if !validPolicyRule(*r) || r.Subject != subject || r.Action != action || r.Resource != resource {
			return wire.PolicyEdit{}, errors.New("rights: mismatched current rule")
		}
	}
	if result.Outcome == "applied" {
		if (permit != nil) != (result.Current != nil) || (permit != nil && result.Current.Permit != *permit) {
			return wire.PolicyEdit{}, errors.New("rights: malformed applied state")
		}
	}
	return result, nil
}
