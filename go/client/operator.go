package client

import (
	"context"
	"encoding/json"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
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
	return boundedOperatorString(r.Subject.Account, 128) && boundedOperatorString(r.Subject.Program, 4096) && identity.ValidSubjectProgram(r.Subject.Program) && boundedOperatorString(r.Action, 128) && boundedOperatorString(r.Resource, 1024)
}

// normalizeOperatorSubject uses the same program spelling as the decision
// policy before sending a rule and checking the rule returned by the service.
func normalizeOperatorSubject(s Subject) Subject {
	s.Program = identity.NormalizeSubjectProgram(s.Program)
	return s
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
	if page.Outcome != wire.PolicyPageOutcomePage {
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
	rule.Subject = normalizeOperatorSubject(rule.Subject)
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
	subject = normalizeOperatorSubject(subject)
	if !boundedOperatorString(expected, 128) || !validPolicyRule(PolicyRule{Subject: subject, Action: action, Resource: resource}) {
		return wire.PolicyEdit{}, errors.New("rights: invalid policy revoke")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RevokeRule(expected, subject, action, resource)
	return checkedPolicyEdit(result, err, subject, action, resource, nil)
}

func (c *Operator) StopAnswererContext(ctx context.Context, expected string, answerer Subject, alsoRevokeGrants bool) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	answerer = normalizeOperatorSubject(answerer)
	if !boundedOperatorString(expected, 128) || !validSubject(answerer) {
		return wire.PolicyEdit{}, errors.New("rights: invalid answerer stop")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).StopAnswerer(expected, answerer, alsoRevokeGrants)
	return checkedAnswerEdit(result, err)
}

func (c *Operator) RevokeAnswerPermitsContext(ctx context.Context, expected string, answerer, target Subject, actions []string, resource, questionID string) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	answerer, target = normalizeOperatorSubject(answerer), normalizeOperatorSubject(target)
	if !boundedOperatorString(expected, 128) || !validSubject(answerer) || !validSubject(target) || !boundedOperatorString(questionID, 128) || len(actions) < 1 || len(actions) > 2 || !boundedOperatorString(resource, 1024) {
		return wire.PolicyEdit{}, errors.New("rights: invalid answer permit revoke")
	}
	for i, action := range actions {
		if !boundedOperatorString(action, 128) || slices.Contains(actions[:i], action) {
			return wire.PolicyEdit{}, errors.New("rights: invalid answer actions")
		}
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RevokeAnswerPermits(expected, answerer, target, actions, resource, questionID)
	return checkedAnswerEdit(result, err)
}

func checkedAnswerEdit(result wire.PolicyEdit, err error) (wire.PolicyEdit, error) {
	if err != nil {
		return wire.PolicyEdit{}, err
	}
	observed := result.Outcome == wire.PolicyEditOutcomeApplied || result.Outcome == wire.PolicyEditOutcomeConflict
	if observed != boundedOperatorString(result.Revision, 128) || result.Current != nil || !observed && result.Revision != "" {
		return wire.PolicyEdit{}, errors.New("rights: malformed answer edit")
	}
	return result, nil
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
	return boundedOperatorString(s.Account, 128) && boundedOperatorString(s.Program, 4096) && identity.ValidSubjectProgram(s.Program)
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

// ApplyFirstUseAllowContext applies the complete permit derived from a retained
// runtime operator Allow. Earlier runtimes return unknown_method; no generic
// setter fallback can preserve its durable completion guarantee.
func (c *Operator) ApplyFirstUseAllowContext(ctx context.Context, expected, id string) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	if !boundedOperatorString(expected, 128) || !boundedOperatorString(id, 128) {
		return wire.PolicyEdit{}, errors.New("rights: invalid first-use Allow")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ApplyFirstUseAllow(expected, id)
	if err != nil {
		return wire.PolicyEdit{}, err
	}
	observed := result.Outcome == wire.PolicyEditOutcomeApplied || result.Outcome == wire.PolicyEditOutcomeConflict
	if observed != boundedOperatorString(result.Revision, 128) || !observed && result.Current != nil || result.Current != nil && !validPolicyRule(*result.Current) || result.Outcome == wire.PolicyEditOutcomeApplied && (result.Current == nil || !result.Current.Permit) {
		return wire.PolicyEdit{}, errors.New("rights: malformed first-use Allow result")
	}
	return result, nil
}

// SetRuleForContext sets one exact rule with a reason and an expiry ttl after the
// service's edit time. A zero ttl sets no expiry.
func (c *Operator) SetRuleForContext(ctx context.Context, expected string, rule PolicyRule, ttl time.Duration, why string) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	rule.Subject = normalizeOperatorSubject(rule.Subject)
	if !boundedOperatorString(expected, 128) || !validPolicyRule(rule) || ttl < 0 || ttl > maxRuleTTL || ttl%time.Millisecond != 0 || !(why == "" || boundedOperatorString(why, 256)) {
		return wire.PolicyEdit{}, errors.New("rights: invalid policy edit")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).SetRuleFor(expected, rule, ttl.Milliseconds(), why)
	return checkedPolicyEdit(result, err, rule.Subject, rule.Action, rule.Resource, &rule.Permit)
}

// SetRulesForContext conditionally sets one or two related exact rules in one
// rights edit, with one provenance stamp and no partial paired permission.
func (c *Operator) SetRulesForContext(ctx context.Context, expected string, rules []PolicyRule, ttl time.Duration, why string) (wire.PolicyEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyEdit{}, err
	}
	if len(rules) < 1 || len(rules) > 2 || !boundedOperatorString(expected, 128) || ttl < 0 || ttl > maxRuleTTL || ttl%time.Millisecond != 0 || !(why == "" || boundedOperatorString(why, 256)) {
		return wire.PolicyEdit{}, errors.New("rights: invalid grouped policy edit")
	}
	for i := range rules {
		rules[i].Subject = normalizeOperatorSubject(rules[i].Subject)
		if !validPolicyRule(rules[i]) || rules[i].Subject.Account != rules[0].Subject.Account || !identity.SameSubjectProgram(rules[i].Subject.Program, rules[0].Subject.Program) || rules[i].Resource != rules[0].Resource || rules[i].Permit != rules[0].Permit || slices.ContainsFunc(rules[:i], func(r PolicyRule) bool { return r.Action == rules[i].Action }) {
			return wire.PolicyEdit{}, errors.New("rights: invalid grouped policy rules")
		}
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).SetRulesFor(expected, rules, ttl.Milliseconds(), why)
	if err != nil {
		return wire.PolicyEdit{}, err
	}
	observed := result.Outcome == wire.PolicyEditOutcomeApplied || result.Outcome == wire.PolicyEditOutcomeConflict
	if observed != boundedOperatorString(result.Revision, 128) || !observed && (result.Revision != "" || result.Current != nil) {
		return wire.PolicyEdit{}, errors.New("rights: malformed grouped edit")
	}
	if result.Current != nil {
		match := slices.ContainsFunc(rules, func(r PolicyRule) bool {
			current := result.Current
			return validPolicyRule(*current) && current.Subject.Account == r.Subject.Account && identity.SameSubjectProgram(current.Subject.Program, r.Subject.Program) && current.Action == r.Action && current.Resource == r.Resource && current.Permit == r.Permit
		})
		if !match {
			return wire.PolicyEdit{}, errors.New("rights: mismatched grouped current rule")
		}
	}
	if result.Outcome == wire.PolicyEditOutcomeApplied && (result.Current == nil || !result.Current.Permit && rules[0].Permit || result.Current.Permit && !rules[0].Permit) {
		return wire.PolicyEdit{}, errors.New("rights: malformed grouped applied state")
	}
	return result, nil
}

// ReadRuleContext reads one exact rule with the provenance the service recorded.
func (c *Operator) ReadRuleContext(ctx context.Context, subject Subject, action, resource string) (wire.RuleRead, error) {
	if err := ctx.Err(); err != nil {
		return wire.RuleRead{}, err
	}
	subject = normalizeOperatorSubject(subject)
	if !validPolicyRule(PolicyRule{Subject: subject, Action: action, Resource: resource}) {
		return wire.RuleRead{}, errors.New("rights: invalid rule read")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ReadRule(subject, action, resource)
	if err != nil {
		return wire.RuleRead{}, err
	}
	switch result.Outcome {
	case wire.RuleReadOutcomeFound, wire.RuleReadOutcomeExpired:
		r := result.Record
		if !boundedOperatorString(result.Revision, 128) || r == nil || !validPolicyRule(r.Rule) || r.Rule.Subject.Account != subject.Account || !identity.SameSubjectProgram(r.Rule.Subject.Program, subject.Program) ||
			r.Rule.Action != action || r.Rule.Resource != resource || !validSubject(r.SetBy) || !validStamp(r.SetAt) ||
			!(r.Why == "" || boundedOperatorString(r.Why, 256)) || (r.Expires != "" && !validStamp(r.Expires)) ||
			(result.Outcome == wire.RuleReadOutcomeExpired && r.Expires == "") {
			return wire.RuleRead{}, errors.New("rights: malformed rule record")
		}
	case wire.RuleReadOutcomeUnknown:
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

// AccountDefault is one account-wide default and its switch (RIGHTS-R22).
type AccountDefault = wire.AccountDefault

// DefaultPage is ListDefaults' answer: every configured default with its
// switch, or a refusal.
type DefaultPage = wire.DefaultPage

// DefaultEdit is SetDefault's answer: the default as it now stands, or a
// refusal.
type DefaultEdit = wire.DefaultEdit

// validAccountDefault checks one default as the service reports it.
func validAccountDefault(d AccountDefault) bool {
	resource := d.EveryResource && d.Resource == "" || !d.EveryResource && boundedOperatorString(d.Resource, 1024)
	provenance := d.SetBy == nil && d.SetAt == "" || d.SetBy != nil && validSubject(*d.SetBy) && validStamp(d.SetAt)
	name := boundedOperatorString(d.Name, 64) && strings.IndexFunc(d.Name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
	}) < 0
	return name && boundedOperatorString(d.Action, 128) && resource && provenance
}

// DecisionExplanation is one exact decision for a subject with the step that
// decided it (RIGHTS-O14).
type DecisionExplanation = wire.DecisionExplanation

// DecisionSource is the step that decided an explained decision.
type DecisionSource = wire.DecisionSource

// The steps an explanation names.
const (
	DecisionSourceNone            = wire.DecisionSourceNone
	DecisionSourceOwnRule         = wire.DecisionSourceOwnRule
	DecisionSourceTypedBlock      = wire.DecisionSourceTypedBlock
	DecisionSourceAccountDefault  = wire.DecisionSourceAccountDefault
	DecisionSourceDefaultExcluded = wire.DecisionSourceDefaultExcluded
)

// DecisionSourceValues returns every step in declaration order.
func DecisionSourceValues() []DecisionSource { return wire.DecisionSourceValues() }

// ExplainForContext reads one exact decision for subject with the step that
// decided it: its own rule, a typed Block, an account-wide default, a default
// the program is excluded from, or none. It asks nobody and records nothing.
// An earlier runtime returns unknown_method.
func (c *Operator) ExplainForContext(ctx context.Context, subject Subject, action, resource string) (wire.DecisionExplanation, error) {
	if err := ctx.Err(); err != nil {
		return wire.DecisionExplanation{}, err
	}
	if !validSubject(subject) || !boundedOperatorString(action, 128) || !boundedOperatorString(resource, 1024) {
		return wire.DecisionExplanation{}, errors.New("rights: invalid explanation request")
	}
	got, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ExplainFor(subject, action, resource)
	if err != nil {
		return wire.DecisionExplanation{}, err
	}
	evaluated := got.Outcome == wire.DecisionOutcomePermitted || got.Outcome == wire.DecisionOutcomeDenied ||
		got.Outcome == wire.DecisionOutcomeNotGranted || got.Outcome == wire.DecisionOutcomeUnknownAction
	if !evaluated {
		if got.PolicyRevision != "" || got.Source != nil || got.DefaultName != "" {
			return wire.DecisionExplanation{}, errors.New("rights: malformed explanation refusal")
		}
		return got, nil
	}
	if !boundedOperatorString(got.PolicyRevision, 128) || got.Source == nil || len(got.DefaultName) > 64 {
		return wire.DecisionExplanation{}, errors.New("rights: malformed explanation")
	}
	named := *got.Source == wire.DecisionSourceAccountDefault || *got.Source == wire.DecisionSourceDefaultExcluded
	if named != (got.DefaultName != "") {
		return wire.DecisionExplanation{}, errors.New("rights: malformed explanation")
	}
	return got, nil
}

// ListDefaultsContext reads every configured account-wide default with its
// switch. An earlier runtime returns unknown_method.
func (c *Operator) ListDefaultsContext(ctx context.Context) (wire.DefaultPage, error) {
	if err := ctx.Err(); err != nil {
		return wire.DefaultPage{}, err
	}
	page, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ListDefaults()
	if err != nil {
		return wire.DefaultPage{}, err
	}
	if page.Outcome != wire.PolicyPageOutcomePage {
		if page.Revision != "" || len(page.Defaults) != 0 {
			return wire.DefaultPage{}, errors.New("rights: malformed defaults refusal")
		}
		return page, nil
	}
	if !boundedOperatorString(page.Revision, 128) || len(page.Defaults) > 32 {
		return wire.DefaultPage{}, errors.New("rights: malformed defaults page")
	}
	for i, d := range page.Defaults {
		if !validAccountDefault(d) || i > 0 && page.Defaults[i-1].Name >= d.Name {
			return wire.DefaultPage{}, errors.New("rights: invalid account default")
		}
	}
	return page, nil
}

// SetDefaultContext turns one configured default on or off at the expected
// revision. A lost reply is uncertain; read the defaults again before another
// edit.
func (c *Operator) SetDefaultContext(ctx context.Context, expected, name string, on bool) (wire.DefaultEdit, error) {
	if err := ctx.Err(); err != nil {
		return wire.DefaultEdit{}, err
	}
	if !boundedOperatorString(expected, 128) || !boundedOperatorString(name, 64) {
		return wire.DefaultEdit{}, errors.New("rights: invalid default edit")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).SetDefault(expected, name, on)
	if err != nil {
		return wire.DefaultEdit{}, err
	}
	observed := result.Outcome == wire.PolicyEditOutcomeApplied || result.Outcome == wire.PolicyEditOutcomeConflict
	if observed != boundedOperatorString(result.Revision, 128) || observed != (result.Current != nil) {
		return wire.DefaultEdit{}, errors.New("rights: malformed default edit")
	}
	if current := result.Current; current != nil && (!validAccountDefault(*current) || current.Name != name || result.Outcome == wire.PolicyEditOutcomeApplied && current.On != on) {
		return wire.DefaultEdit{}, errors.New("rights: mismatched default")
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
	observed := result.Outcome == wire.ActionEditOutcomeApplied || result.Outcome == wire.ActionEditOutcomeConflict || result.Outcome == wire.ActionEditOutcomeUnknown
	if observed != boundedOperatorString(result.Revision, 128) || (result.Current != nil && (result.Outcome == wire.ActionEditOutcomeUnknown || !observed)) {
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
	observed := result.Outcome == wire.PolicyEditOutcomeApplied || result.Outcome == wire.PolicyEditOutcomeConflict
	if observed != boundedOperatorString(result.Revision, 128) || (!observed && (result.Revision != "" || result.Current != nil)) {
		return wire.PolicyEdit{}, errors.New("rights: malformed edit revision")
	}
	if r := result.Current; r != nil {
		if !validPolicyRule(*r) || r.Subject.Account != subject.Account || !identity.SameSubjectProgram(r.Subject.Program, subject.Program) || r.Action != action || r.Resource != resource {
			return wire.PolicyEdit{}, errors.New("rights: mismatched current rule")
		}
	}
	if result.Outcome == wire.PolicyEditOutcomeApplied {
		if (permit != nil) != (result.Current != nil) || (permit != nil && result.Current.Permit != *permit) {
			return wire.PolicyEdit{}, errors.New("rights: malformed applied state")
		}
	}
	return result, nil
}
