package rights

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// Account-wide defaults (RIGHTS-R22; VISION 2026-10-07): a named permit on one
// action for every program of the runtime's own account that has no live rule
// of its own on the queried target. Each default is one switch, on until an
// operator turns it off. A default writes no rule.

// The installed runtime's default names, in the order the Panel shows them.
const (
	DefaultRegister = "register"
	DefaultAsk      = "ask"
	DefaultAnnounce = "announce"
	DefaultNotify   = "notify"
	DefaultDownload = "download"
)

// The actions the runtime's defaults name; the notify default's action is the
// facade grants' NotificationPostAction, and the list itself is
// grants.RuntimeAccountDefaults. ActionApplicationRegisterSelf is the
// Applications service's Register of the caller's own program (facade
// APPLICATIONS.md).
const (
	ActionApplicationRegisterSelf = "abstraction.facade/application.register_self"
	ActionApplicationAnnounce     = "abstraction.facade/application.announce"
	ActionQuestionAsk             = "abstraction.asks/question.ask"
	ActionJobSubmit               = "abstraction.job/acceptance.submit"
	ResourceAccount               = "account"
	ResourceDownloadJobs          = "job:download"
)

// MaxAccountDefaults bounds the configured defaults.
const MaxAccountDefaults = 32

// AccountDefault is one configured default: a permit on Action for Resource
// exactly, or for every resource of Action with EveryResource.
type AccountDefault struct {
	Name          string
	Action        string
	Resource      string
	EveryResource bool
}

// defaultSwitch is one turned switch in the decision file. A configured
// default with no entry is on.
type defaultSwitch struct {
	Name  string       `json:"name"`
	On    bool         `json:"on"`
	SetBy wire.Subject `json:"set_by"`
	SetAt string       `json:"set_at"`
}

// validDefaultName is a switch name: 1..64 bytes of lowercase ASCII letters,
// digits, '.', '_' and '-', beginning with a letter or digit.
func validDefaultName(name string) bool { return actionPart(name, 64) }

func validDefaultSwitches(switches []defaultSwitch) error {
	if len(switches) > MaxAccountDefaults {
		return errors.New("rights: default switch bound")
	}
	for i, s := range switches {
		if !validDefaultName(s.Name) || !validStoredSubject(s.SetBy) || !validStamp(s.SetAt) || i > 0 && switches[i-1].Name >= s.Name {
			return errors.New("rights: invalid/duplicate default switch")
		}
	}
	return nil
}

// ConfigureDefaults sets the account-wide defaults this policy evaluates, the
// one account whose programs receive them, and the programs excluded from
// every default (a script host). An empty account gives nobody a default.
// Configure before the policy is shared; the defaults join the revision.
func (p *DecisionPolicy) ConfigureDefaults(account string, defaults []AccountDefault, excluded func(wire.Subject) bool) error {
	if len(defaults) > MaxAccountDefaults || (account != "" && !boundedDecisionString(account, 128)) {
		return errors.New("rights: invalid account defaults")
	}
	seen := map[string]bool{}
	for _, d := range defaults {
		if !validDefaultName(d.Name) || seen[d.Name] || !ValidActionName(d.Action) && !slices.Contains(p.seed, d.Action) ||
			d.EveryResource != (d.Resource == "") || (!d.EveryResource && !ValidDecisionQuery(d.Action, d.Resource)) {
			return errors.New("rights: invalid account default " + d.Name)
		}
		seen[d.Name] = true
	}
	p.defaults = slices.Clone(defaults)
	p.defaultAccount = account
	p.defaultExcluded = excluded
	p.decoded.reset()
	return nil
}

// defaultsDigest identifies the configured defaults for the revision; empty
// when none are configured, so a policy without defaults keeps its revision.
func (p *DecisionPolicy) defaultsDigest() string {
	if len(p.defaults) == 0 {
		return ""
	}
	//unchecked: plain marshalable data that only feeds the digest below
	data, _ := json.Marshal(struct {
		Account  string
		Defaults []AccountDefault
	}{p.defaultAccount, p.defaults})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// switchOn reports whether the named default is on in f.
func switchOn(f decisionFile, name string) bool {
	for _, s := range f.DefaultSwitches {
		if s.Name == name {
			return s.On
		}
	}
	return true
}

// defaultVerdict is what the account-wide defaults say about one target.
type defaultVerdict int

const (
	defaultNone            defaultVerdict = iota // no default switched on covers it
	defaultPermits                               // a default permits it
	defaultExcludesProgram                       // a default covers it; the program is excluded
)

// defaultFor reports whether an account-wide default permits s on the
// target, naming the default. The caller has found no live rule of s's own
// there. A default switched on for the target that the configured exclusion
// keeps from s is reported as such, so an operator can say why.
func (p *DecisionPolicy) defaultFor(f decisionFile, s wire.Subject, action, resource string) (string, defaultVerdict) {
	if p.defaultAccount == "" || s.Account != p.defaultAccount {
		return "", defaultNone
	}
	excluded := false
	checked := false
	for _, d := range p.defaults {
		if d.Action != action || (!d.EveryResource && d.Resource != resource) || !switchOn(f, d.Name) {
			continue
		}
		if !checked {
			excluded, checked = p.defaultExcluded != nil && p.defaultExcluded(s), true
		}
		if excluded {
			return d.Name, defaultExcludesProgram
		}
		return d.Name, defaultPermits
	}
	return "", defaultNone
}

func (p *DecisionPolicy) publicDefault(f decisionFile, d AccountDefault) wire.AccountDefault {
	out := wire.AccountDefault{Name: d.Name, Action: d.Action, Resource: d.Resource, EveryResource: d.EveryResource, On: true}
	for _, s := range f.DefaultSwitches {
		if s.Name == d.Name {
			by := s.SetBy
			out.On, out.SetBy, out.SetAt = s.On, &by, s.SetAt
		}
	}
	return out
}

// DefaultsSnapshot returns every configured default with its switch, sorted by
// name, and the revision they were read at. Callers authorize first.
func (p *DecisionPolicy) DefaultsSnapshot(ctx context.Context) (string, []wire.AccountDefault, error) {
	f, revision, err := p.readDecisionContext(ctx)
	if err != nil {
		return "", nil, err
	}
	out := make([]wire.AccountDefault, 0, len(p.defaults))
	for _, d := range p.defaults {
		out = append(out, p.publicDefault(f, d))
	}
	slices.SortFunc(out, func(a, b wire.AccountDefault) int { return strings.Compare(a.Name, b.Name) })
	return revision, out, nil
}

// SetDefault turns one configured default on or off at the expected revision,
// recording by and the service time. authorize is rechecked inside the edit.
// An unconfigured name is invalid; a switch already in the requested state is
// a no-op that keeps the revision.
func (p *DecisionPolicy) SetDefault(expected, name string, on bool, by wire.Subject, authorize func() error) (wire.DefaultEdit, error) {
	by, err := NormalizeDecisionSubject(by)
	index := slices.IndexFunc(p.defaults, func(d AccountDefault) bool { return d.Name == name })
	if err != nil || index < 0 || !boundedDecisionString(expected, 128) {
		return wire.DefaultEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	if authorize == nil {
		return wire.DefaultEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err = p.regular(); err != nil {
		return wire.DefaultEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	configured := p.defaults[index]
	result := wire.DefaultEdit{}
	noWrite := errors.New("rights: default edit without write")
	at := stamp(p.now())
	capture := func(f decisionFile) {
		result.Revision = p.revision(f)
		current := p.publicDefault(f, configured)
		result.Current = &current
	}
	err = p.change(func(data []byte) ([]byte, error) {
		result = wire.DefaultEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if p.revision(f) != expected {
			result.Outcome = wire.PolicyEditOutcomeConflict
			capture(f)
			return nil, noWrite
		}
		result.Outcome = wire.PolicyEditOutcomeApplied
		if switchOn(f, name) == on {
			capture(f)
			return nil, noWrite
		}
		f.DefaultSwitches = slices.DeleteFunc(f.DefaultSwitches, func(s defaultSwitch) bool { return s.Name == name })
		f.DefaultSwitches = append(f.DefaultSwitches, defaultSwitch{Name: name, On: on, SetBy: by, SetAt: at})
		slices.SortFunc(f.DefaultSwitches, func(a, b defaultSwitch) int { return strings.Compare(a.Name, b.Name) })
		f.Profile = DecisionProfile
		capture(f)
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if err != nil {
		return wire.DefaultEdit{Outcome: wire.PolicyEditOutcomeUnavailable}, err
	}
	return result, nil
}
