package rights

import (
	"bytes"
	"encoding/json"
	"errors"
	cas "github.com/openabstractions/abstraction-cas/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DecisionProfile names the persisted decision state. Version 2 stores
// registered actions, rule provenance and rule expiry; version 1 files refuse.
const DecisionProfile = "rights-decisions@2"
const MaxDecisionBytes = 4 << 20
const MaxDecisionRules = 4096
const MaxDecisionActions = 64

// MaxRuleTTL bounds a rule's expiry after its edit time.
const MaxRuleTTL = 365 * 24 * time.Hour

// MaxRuleWhy bounds the operator's recorded reason in bytes.
const MaxRuleWhy = 256

// StampFormat is the UTC service time carried by provenance and expiry.
const StampFormat = "2006-01-02T15:04:05.000Z"

// ErrCatalogueFull reports a registration beyond MaxDecisionActions.
var ErrCatalogueFull = errors.New("rights: catalogue holds the maximum number of actions")

type decisionRule struct {
	Subject  wire.Subject `json:"subject"`
	Action   string       `json:"action"`
	Resource string       `json:"resource"`
	Permit   bool         `json:"permit"`
	SetBy    wire.Subject `json:"set_by"`
	SetAt    string       `json:"set_at"`
	Why      string       `json:"why,omitempty"`
	Expires  string       `json:"expires,omitempty"`
}
type registeredAction struct {
	Action string       `json:"action"`
	By     wire.Subject `json:"by"`
	At     string       `json:"at"`
}
type decisionFile struct {
	Profile string             `json:"profile"`
	Actions []registeredAction `json:"actions"`
	Rules   []decisionRule     `json:"rules"`
}

// DecisionPolicy owns a separate service-only state file. Native Set/Revoke and
// RegisterAction are operator authority, never application methods. The catalogue
// is the configured seed plus actions registered in the file.
type DecisionPolicy struct {
	path   string
	seed   []string
	native wire.Subject
	// Clock supplies service time for provenance and expiry. Nil uses time.Now.
	// Assign before the policy is shared.
	Clock func() time.Time
}

func boundedDecisionString(v string, max int) bool {
	return len(v) > 0 && len(v) <= max && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func validWhy(v string) bool {
	return v == "" || boundedDecisionString(v, MaxRuleWhy)
}
func NormalizeDecisionSubject(s wire.Subject) (wire.Subject, error) {
	if !boundedDecisionString(s.Account, 128) || !boundedDecisionString(s.Program, 4096) || !filepath.IsAbs(s.Program) {
		return wire.Subject{}, errors.New("rights: invalid subject")
	}
	s.Program = filepath.Clean(s.Program)
	return s, nil
}
func ValidDecisionQuery(action, resource string) bool {
	return boundedDecisionString(action, 128) && boundedDecisionString(resource, 1024)
}

// ValidActionName reports whether action is a registrable <owner>/<name>.
func ValidActionName(action string) bool {
	owner, name, ok := strings.Cut(action, "/")
	return ok && actionPart(owner, 64) && actionPart(name, 63)
}
func actionPart(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func validStamp(s string) bool {
	t, e := time.Parse(StampFormat, s)
	return e == nil && t.UTC().Format(StampFormat) == s
}
func stamp(t time.Time) string { return t.UTC().Format(StampFormat) }

// LoadDecisionPolicy configures the seed catalogue and validates the file. The
// seed may be any bounded exact strings; registered actions use <owner>/<name>.
// A file whose rules name an action outside seed and registrations refuses.
func LoadDecisionPolicy(path string, seed []string) (*DecisionPolicy, error) {
	if len(seed) == 0 || len(seed) > MaxDecisionActions {
		return nil, errors.New("rights: seed catalogue needs 1..64 actions")
	}
	seed = slices.Clone(seed)
	slices.Sort(seed)
	for i, a := range seed {
		if !boundedDecisionString(a, 128) || (i > 0 && seed[i-1] == a) {
			return nil, errors.New("rights: invalid/duplicate catalogue action")
		}
	}
	native, e := serviceSubject()
	if e != nil {
		return nil, e
	}
	p := &DecisionPolicy{path: path, seed: seed, native: native}
	_, _, e = p.readDecision()
	return p, e
}
func serviceSubject() (wire.Subject, error) {
	u, e := user.Current()
	if e != nil {
		return wire.Subject{}, e
	}
	exe, e := os.Executable()
	if e != nil {
		return wire.Subject{}, e
	}
	return NormalizeDecisionSubject(wire.Subject{Account: u.Uid, Program: exe})
}
func (p *DecisionPolicy) now() time.Time {
	if p.Clock != nil {
		return p.Clock().UTC()
	}
	return time.Now().UTC()
}
func (p *DecisionPolicy) regular() error {
	info, e := os.Lstat(p.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("rights: decision state must be regular")
	}
	return nil
}
func ruleKey(r decisionRule) string {
	return r.Subject.Account + "\x00" + r.Subject.Program + "\x00" + r.Action + "\x00" + r.Resource
}
func (p *DecisionPolicy) catalogue(f decisionFile) []string {
	all := slices.Clone(p.seed)
	for _, a := range f.Actions {
		if !slices.Contains(all, a.Action) {
			all = append(all, a.Action)
		}
	}
	slices.Sort(all)
	return all
}
func expired(r decisionRule, now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	t, e := time.Parse(StampFormat, r.Expires)
	return e != nil || !now.Before(t)
}
func (p *DecisionPolicy) decodeDecision(data []byte) (decisionFile, error) {
	var f decisionFile
	if data == nil {
		return decisionFile{Profile: DecisionProfile}, nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&f); e != nil {
		return f, e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return f, errors.New("rights: trailing state")
	}
	if f.Profile != DecisionProfile || len(f.Rules) > MaxDecisionRules || len(f.Actions) > MaxDecisionActions {
		return f, errors.New("rights: incompatible decision state")
	}
	for i, a := range f.Actions {
		by, e := NormalizeDecisionSubject(a.By)
		if e != nil || by != a.By || !ValidActionName(a.Action) || !validStamp(a.At) || (i > 0 && f.Actions[i-1].Action >= a.Action) {
			return f, errors.New("rights: invalid/duplicate registered action")
		}
	}
	catalogue := p.catalogue(f)
	if len(catalogue) > MaxDecisionActions {
		return f, errors.New("rights: catalogue exceeds its bound")
	}
	last := ""
	for _, r := range f.Rules {
		s, e := NormalizeDecisionSubject(r.Subject)
		by, byErr := NormalizeDecisionSubject(r.SetBy)
		key := ruleKey(r)
		if e != nil || byErr != nil || s != r.Subject || by != r.SetBy || !ValidDecisionQuery(r.Action, r.Resource) ||
			!slices.Contains(catalogue, r.Action) || key <= last || !validStamp(r.SetAt) || !validWhy(r.Why) ||
			(r.Expires != "" && !validStamp(r.Expires)) {
			return f, errors.New("rights: invalid/duplicate rule")
		}
		last = key
	}
	canonical, e := json.Marshal(f)
	if e != nil || !bytes.Equal(data, canonical) {
		return f, errors.New("rights: noncanonical decision state")
	}
	return f, nil
}
func (p *DecisionPolicy) readDecision() (decisionFile, string, error) {
	if e := p.regular(); e != nil {
		return decisionFile{}, "", e
	}
	data, e := cas.ReadLimit(p.path, MaxDecisionBytes)
	if e != nil {
		return decisionFile{}, "", e
	}
	f, e := p.decodeDecision(data)
	if e != nil {
		return f, "", e
	}
	return f, p.revision(f), nil
}

// ruleChange is one edit of an exact rule. A nil permit revokes. exact compares
// reason and expiry as well as permit when deciding whether the edit is a no-op.
type ruleChange struct {
	permit  *bool
	by      wire.Subject
	at      time.Time
	ttl     time.Duration
	why     string
	exact   bool
	missing error
}

func (p *DecisionPolicy) editDecision(subject wire.Subject, action, resource string, permit *bool) error {
	s, e := NormalizeDecisionSubject(subject)
	if e != nil || !ValidDecisionQuery(action, resource) {
		return errors.New("rights: invalid exact rule")
	}
	if e = p.regular(); e != nil {
		return e
	}
	change := ruleChange{permit: permit, by: p.native, at: p.now()}
	return cas.ChangeLimit(p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		if !slices.Contains(p.catalogue(f), action) {
			return nil, ErrUnknownRight
		}
		changed, e := applyDecisionRule(&f, s, action, resource, change)
		if e != nil {
			return nil, e
		}
		if !changed {
			return data, nil
		}
		return json.Marshal(f)
	})
}
func (p *DecisionPolicy) Set(subject wire.Subject, action, resource string, permit bool) error {
	return p.editDecision(subject, action, resource, &permit)
}
func (p *DecisionPolicy) Revoke(subject wire.Subject, action, resource string) error {
	return p.editDecision(subject, action, resource, nil)
}

// RegisterAction adds a <owner>/<name> action to the catalogue with the service's
// own subject as registrant. An action already in the catalogue writes nothing.
func (p *DecisionPolicy) RegisterAction(action string) error {
	if !ValidActionName(action) {
		return errors.New("rights: invalid action name")
	}
	if e := p.regular(); e != nil {
		return e
	}
	at := stamp(p.now())
	return cas.ChangeLimit(p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		if slices.Contains(p.catalogue(f), action) {
			return data, nil
		}
		if len(p.catalogue(f)) >= MaxDecisionActions {
			return nil, ErrCatalogueFull
		}
		addAction(&f, registeredAction{Action: action, By: p.native, At: at})
		return json.Marshal(f)
	})
}

// Catalogue returns the current seed plus registered actions, sorted.
func (p *DecisionPolicy) Catalogue() ([]string, error) {
	f, _, e := p.readDecision()
	if e != nil {
		return nil, e
	}
	return p.catalogue(f), nil
}
func addAction(f *decisionFile, entry registeredAction) {
	f.Actions = append(f.Actions, entry)
	slices.SortFunc(f.Actions, func(a, b registeredAction) int { return strings.Compare(a.Action, b.Action) })
}
func (p *DecisionPolicy) Decide(subject wire.Subject, action, resource string) wire.Decision {
	s, e := NormalizeDecisionSubject(subject)
	if e != nil || !ValidDecisionQuery(action, resource) {
		return wire.Decision{Outcome: wire.DecisionOutcomeInvalid}
	}
	f, revision, e := p.readDecision()
	if e != nil {
		return wire.Decision{Outcome: wire.DecisionOutcomeUnavailable}
	}
	result := wire.Decision{Outcome: wire.DecisionOutcomeNotGranted, PolicyRevision: revision}
	if !slices.Contains(p.catalogue(f), action) {
		result.Outcome = wire.DecisionOutcomeUnknownAction
		return result
	}
	now := p.now()
	for _, r := range f.Rules {
		if r.Subject == s && r.Action == action && r.Resource == resource {
			if expired(r, now) {
				break
			}
			result.Outcome = wire.DecisionOutcomeDenied
			if r.Permit {
				result.Outcome = wire.DecisionOutcomePermitted
			}
			break
		}
	}
	return result
}

// pruneExpired removes every rule at or past its expiry.
func pruneExpired(f *decisionFile, now time.Time) {
	f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return expired(r, now) })
	if len(f.Rules) == 0 {
		f.Rules = nil
	}
}
func applyDecisionRule(f *decisionFile, s wire.Subject, action, resource string, change ruleChange) (bool, error) {
	key := ruleKey(decisionRule{Subject: s, Action: action, Resource: resource})
	find := func() int { return slices.IndexFunc(f.Rules, func(r decisionRule) bool { return ruleKey(r) == key }) }
	index := find()
	if change.permit == nil {
		if index < 0 {
			return false, change.missing
		}
		f.Rules = slices.Delete(f.Rules, index, index+1)
		pruneExpired(f, change.at)
		return true, nil
	}
	r := decisionRule{Subject: s, Action: action, Resource: resource, Permit: *change.permit, SetBy: change.by, SetAt: stamp(change.at), Why: change.why}
	if change.ttl > 0 {
		r.Expires = stamp(change.at.Add(change.ttl))
	}
	if index >= 0 {
		old := f.Rules[index]
		same := old.Permit == r.Permit && !expired(old, change.at)
		if change.exact {
			same = same && old.Why == r.Why && old.Expires == r.Expires
		}
		if same {
			return false, nil
		}
		f.Rules[index] = r
	} else {
		pruneExpired(f, change.at)
		if len(f.Rules) >= MaxDecisionRules {
			return false, errors.New("rights: rule capacity reached")
		}
		f.Rules = append(f.Rules, r)
	}
	pruneKeep(f, key, change.at)
	slices.SortFunc(f.Rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	return true, nil
}

// pruneKeep removes expired rules other than the rule just written.
func pruneKeep(f *decisionFile, key string, now time.Time) {
	f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return ruleKey(r) != key && expired(r, now) })
}
