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

type RuleRecord = wire.RuleRecord
type CatalogEntry = wire.CatalogEntry

const stampFormat = "2006-01-02T15:04:05.000Z"
const maxRuleTTL = 365 * 24 * time.Hour

func validStamp(s string) bool {
	t, err := time.Parse(stampFormat, s)
	return err == nil && t.UTC().Format(stampFormat) == s
}
func validSubject(s Subject) bool {
	return boundedOperatorString(s.Account, 128) && boundedOperatorString(s.Program, 4096) && filepath.IsAbs(s.Program) && filepath.Clean(s.Program) == s.Program
}
func validActionName(action string) bool {
	owner, name, ok := strings.Cut(action, "/")
	part := func(s string, max int) bool {
		if len(s) == 0 || len(s) > max {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-')) {
				return false
			}
		}
		return true
	}
	return ok && part(owner, 64) && part(name, 63)
}

// SetRuleForContext sets one exact rule with a reason and an expiry ttl after the
// service's edit time. A zero ttl sets no expiry.
func (c *Operator) SetRuleForContext(ctx context.Context, expected string, rule PolicyRule, ttl time.Duration, why string) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	rule.Subject.Program = filepath.Clean(rule.Subject.Program)
	if !boundedOperatorString(expected, 128) || !validPolicyRule(rule) || ttl < 0 || ttl > maxRuleTTL || ttl%time.Millisecond != 0 || !(why == "" || boundedOperatorString(why, 256)) {
		return wire.PolicyEdit{}, errors.New("rights: invalid policy edit")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).SetRuleFor(expected, rule, ttl.Milliseconds(), why)
	return checkedPolicyEdit(result, err, rule.Subject, rule.Action, rule.Resource, &rule.Permit)
}

// ReadRuleContext reads one exact rule with the provenance the service recorded.
func (c *Operator) ReadRuleContext(ctx context.Context, subject Subject, action, resource string) (wire.RuleRead, error) {
	if err := ctx.Err(); err != nil {
		return wire.RuleRead{}, err
	}
	subject.Program = filepath.Clean(subject.Program)
	if !validPolicyRule(PolicyRule{Subject: subject, Action: action, Resource: resource}) {
		return wire.RuleRead{}, errors.New("rights: invalid rule read")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ReadRule(subject, action, resource)
	if err != nil {
		return wire.RuleRead{}, err
	}
	switch result.Outcome {
	case "found", "expired":
		r := result.Record
		if !boundedOperatorString(result.Revision, 128) || r == nil || !validPolicyRule(r.Rule) || r.Rule.Subject != subject ||
			r.Rule.Action != action || r.Rule.Resource != resource || !validSubject(r.SetBy) || !validStamp(r.SetAt) ||
			!(r.Why == "" || boundedOperatorString(r.Why, 256)) || (r.Expires != "" && !validStamp(r.Expires)) ||
			(result.Outcome == "expired" && r.Expires == "") {
			return wire.RuleRead{}, errors.New("rights: malformed rule record")
		}
	case "unknown":
		if !boundedOperatorString(result.Revision, 128) || result.Record != nil {
			return wire.RuleRead{}, errors.New("rights: malformed unknown rule")
		}
	default:
		if result.Revision != "" || result.Record != nil {
			return wire.RuleRead{}, errors.New("rights: malformed rule refusal")
		}
	}
	return result, nil
}

// RegisterActionContext conditionally adds an <owner>/<name> action to the catalogue.
func (c *Operator) RegisterActionContext(ctx context.Context, expected, action string) (wire.ActionEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.ActionEdit{}, err
	}
	if !boundedOperatorString(expected, 128) || !validActionName(action) {
		return wire.ActionEdit{}, errors.New("rights: invalid action registration")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RegisterAction(expected, action)
	return checkedActionEdit(result, err, action)
}

// RetireActionContext conditionally removes a registered action and its rules.
func (c *Operator) RetireActionContext(ctx context.Context, expected, action string) (wire.ActionEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.ActionEdit{}, err
	}
	if !boundedOperatorString(expected, 128) || !boundedOperatorString(action, 128) {
		return wire.ActionEdit{}, errors.New("rights: invalid action retirement")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RetireAction(expected, action)
	return checkedActionEdit(result, err, action)
}
func checkedActionEdit(result wire.ActionEdit, err error, action string) (wire.ActionEdit, error) {
	if err != nil {
		return wire.ActionEdit{}, err
	}
	observed := result.Outcome == "applied" || result.Outcome == "conflict" || result.Outcome == "unknown"
	if observed != boundedOperatorString(result.Revision, 128) || (result.Current != nil && (result.Outcome == "unknown" || !observed)) {
		return wire.ActionEdit{}, errors.New("rights: malformed action edit")
	}
	if e := result.Current; e != nil && (e.Action != action || !validSubject(e.RegisteredBy) || !validStamp(e.RegisteredAt)) {
		return wire.ActionEdit{}, errors.New("rights: mismatched catalogue entry")
	}
	return result, nil
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
