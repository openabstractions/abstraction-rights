package rights

import (
	"bytes"
	"encoding/json"
	"errors"
	cas "github.com/openabstractions/abstraction-cas/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const DecisionProfile = "rights-decisions@1"
const MaxDecisionBytes = 4 << 20
const MaxDecisionRules = 4096
const MaxDecisionActions = 64

type decisionRule struct {
	Subject  wire.Subject `json:"subject"`
	Action   string       `json:"action"`
	Resource string       `json:"resource"`
	Permit   bool         `json:"permit"`
}
type decisionFile struct {
	Profile string         `json:"profile"`
	Catalog []string       `json:"catalog"`
	Rules   []decisionRule `json:"rules"`
}

// DecisionPolicy owns a separate service-only state file. Native Set/Revoke are
// operator authority, never application methods. The catalog is immutable.
type DecisionPolicy struct {
	path    string
	catalog []string
}

func boundedDecisionString(v string, max int) bool {
	return len(v) > 0 && len(v) <= max && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
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
func LoadDecisionPolicy(path string, catalog []string) (*DecisionPolicy, error) {
	if len(catalog) == 0 || len(catalog) > MaxDecisionActions {
		return nil, errors.New("rights: catalog needs 1..64 actions")
	}
	catalog = slices.Clone(catalog)
	slices.Sort(catalog)
	for i, a := range catalog {
		if !boundedDecisionString(a, 128) || (i > 0 && catalog[i-1] == a) {
			return nil, errors.New("rights: invalid/duplicate catalog action")
		}
	}
	p := &DecisionPolicy{path: path, catalog: catalog}
	_, _, e := p.readDecision()
	return p, e
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
func (p *DecisionPolicy) decodeDecision(data []byte) (decisionFile, error) {
	var f decisionFile
	if data == nil {
		return decisionFile{Profile: DecisionProfile, Catalog: slices.Clone(p.catalog)}, nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&f); e != nil {
		return f, e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return f, errors.New("rights: trailing state")
	}
	if f.Profile != DecisionProfile || !slices.Equal(f.Catalog, p.catalog) || len(f.Rules) > MaxDecisionRules {
		return f, errors.New("rights: incompatible decision state")
	}
	last := ""
	for _, r := range f.Rules {
		s, e := NormalizeDecisionSubject(r.Subject)
		key := ruleKey(r)
		if e != nil || s != r.Subject || !ValidDecisionQuery(r.Action, r.Resource) || !slices.Contains(p.catalog, r.Action) || key <= last {
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
	return f, decisionRevision(f), nil
}
func (p *DecisionPolicy) editDecision(subject wire.Subject, action, resource string, permit *bool) error {
	s, e := NormalizeDecisionSubject(subject)
	if e != nil || !ValidDecisionQuery(action, resource) {
		return errors.New("rights: invalid exact rule")
	}
	if !slices.Contains(p.catalog, action) {
		return ErrUnknownRight
	}
	if e = p.regular(); e != nil {
		return e
	}
	return cas.ChangeLimit(p.path, MaxDecisionBytes, func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		changed, e := applyDecisionRule(&f, s, action, resource, permit)
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
	if !slices.Contains(f.Catalog, action) {
		result.Outcome = wire.DecisionOutcomeUnknownAction
		return result
	}
	for _, r := range f.Rules {
		if r.Subject == s && r.Action == action && r.Resource == resource {
			result.Outcome = wire.DecisionOutcomeDenied
			if r.Permit {
				result.Outcome = wire.DecisionOutcomePermitted
			}
			break
		}
	}
	return result
}

func applyDecisionRule(f *decisionFile, s wire.Subject, action, resource string, permit *bool) (bool, error) {
	key := ruleKey(decisionRule{Subject: s, Action: action, Resource: resource})
	index := slices.IndexFunc(f.Rules, func(r decisionRule) bool { return ruleKey(r) == key })
	if permit == nil {
		if index < 0 {
			return false, nil
		}
		f.Rules = slices.Delete(f.Rules, index, index+1)
		if len(f.Rules) == 0 {
			f.Rules = nil
		}
	} else {
		r := decisionRule{s, action, resource, *permit}
		if index >= 0 {
			if f.Rules[index].Permit == *permit {
				return false, nil
			}
			f.Rules[index] = r
		} else {
			if len(f.Rules) >= MaxDecisionRules {
				return false, errors.New("rights: rule capacity reached")
			}
			f.Rules = append(f.Rules, r)
		}
	}
	slices.SortFunc(f.Rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	return true, nil
}
