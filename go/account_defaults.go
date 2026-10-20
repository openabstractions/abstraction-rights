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
	// DefaultAgentMessages lets the person's kept agents message each other.
	// It is off after a fresh install and covers only the host's agent class.
	DefaultAgentMessages = "agent-messages"
	// DefaultElevatedCallers lets an elevated local native peer of the
	// account act without a question (ElevatedCallersDefault).
	DefaultElevatedCallers = "elevated-callers"
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

// EveryActionName is the action ListDefaults reports for a default over every
// action.
const EveryActionName = "*"

// MaxAccountDefaults bounds the configured defaults.
const MaxAccountDefaults = 32

// AccountDefault is one configured default: a permit on Action for Resource
// exactly, or for every resource of Action with EveryResource. EveryAction,
// with EveryResource and an empty Action, permits every registered action on
// every resource, typed targets included.
//
// Off makes the switch off after a fresh install, on only once an operator
// turns it on. Covers, when set, is a host class: a predicate over the subject
// and resource read at each decision, and the default permits only targets it
// covers. It reads the decision's context, which carries the peer the
// receiving service bound (WithBoundPeer). Class membership is a current host
// fact and contributes nothing to the revision. Covers must be safe under the
// policy CAS and acquire no directory or RPC locks. A nil Covers covers every
// subject of the account. AllPrograms exempts the default from the configured
// program exclusion.
type AccountDefault struct {
	Name          string
	Action        string
	Resource      string
	EveryResource bool
	EveryAction   bool                                             `json:",omitempty"`
	AllPrograms   bool                                             `json:",omitempty"`
	Off           bool                                             `json:",omitempty"`
	Covers        func(context.Context, wire.Subject, string) bool `json:"-"`
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
		if !validDefaultName(s.Name) || !validStoredActor(s.SetBy) || !validStamp(s.SetAt) || i > 0 && switches[i-1].Name >= s.Name {
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
	if p.revisionConfiguration != "" {
		return errors.New("rights: revision configuration frozen")
	}
	if len(defaults) > MaxAccountDefaults || (account != "" && !boundedDecisionString(account, 128)) {
		return errors.New("rights: invalid account defaults")
	}
	seen := map[string]bool{}
	for _, d := range defaults {
		everyAction := d.EveryAction && d.Action == "" && d.EveryResource
		if !validDefaultName(d.Name) || seen[d.Name] || d.EveryAction && !everyAction || !everyAction && !ValidActionName(d.Action) && !slices.Contains(p.seed, d.Action) ||
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

// switchOn reports whether default d is on in f: its turned switch, else its
// configured fresh-install state.
func switchOn(f decisionFile, d AccountDefault) bool {
	for _, s := range f.DefaultSwitches {
		if s.Name == d.Name {
			return s.On
		}
	}
	return !d.Off
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
// keeps from s is reported as such, so an operator can say why, unless a
// default exempt from the exclusion (AllPrograms) permits. ctx is the
// decision's; each default's class reads it.
func (p *DecisionPolicy) defaultFor(ctx context.Context, f decisionFile, s wire.Subject, action, resource string) (string, defaultVerdict) {
	return p.firstDefault(ctx, f, s, resource, func(d AccountDefault) bool {
		return d.EveryAction || d.Action == action && (d.EveryResource || d.Resource == resource)
	})
}

// everyActionDefault is defaultFor for a typed target, which only a default
// over every action covers. Its class reads no resource.
func (p *DecisionPolicy) everyActionDefault(ctx context.Context, f decisionFile, s wire.Subject) (string, defaultVerdict) {
	return p.firstDefault(ctx, f, s, "", func(d AccountDefault) bool { return d.EveryAction })
}

func (p *DecisionPolicy) firstDefault(ctx context.Context, f decisionFile, s wire.Subject, resource string, applies func(AccountDefault) bool) (string, defaultVerdict) {
	if remoteSubject(s) {
		return "", defaultNone
	}
	if p.defaultAccount == "" || s.Account != p.defaultAccount {
		return "", defaultNone
	}
	excludedName := ""
	excluded := false
	checked := false
	for _, d := range p.defaults {
		if !applies(d) || !switchOn(f, d) || d.Covers != nil && !d.Covers(ctx, s, resource) {
			continue
		}
		if d.AllPrograms {
			return d.Name, defaultPermits
		}
		if !checked {
			excluded, checked = p.defaultExcluded != nil && p.defaultExcluded(s), true
		}
		if !excluded {
			return d.Name, defaultPermits
		}
		if excludedName == "" {
			excludedName = d.Name
		}
	}
	if excludedName != "" {
		return excludedName, defaultExcludesProgram
	}
	return "", defaultNone
}

func (p *DecisionPolicy) publicDefault(f decisionFile, d AccountDefault) wire.AccountDefault {
	out := wire.AccountDefault{Name: d.Name, Action: d.Action, Resource: d.Resource, EveryResource: d.EveryResource, On: !d.Off}
	if d.EveryAction {
		// operator@1 has no field for every action; its action reads "*",
		// which names no registered action (RIGHTS-R27).
		out.Action = EveryActionName
	}
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
	by, err := normalizeActor(by)
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
		if switchOn(f, configured) == on {
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

// everyActionTyped lets a default over every action permit the typed targets
// of one snapshot that no rule decided (RIGHTS-R27). Its defaults are read at
// most once, on the first not_granted outcome.
type everyActionTyped struct {
	p       *DecisionPolicy
	ctx     context.Context
	f       decisionFile
	s       wire.Subject
	read    bool
	permits bool
}

func (e *everyActionTyped) apply(outcome wire.DecisionOutcome) wire.DecisionOutcome {
	if outcome != wire.DecisionOutcomeNotGranted {
		return outcome
	}
	if !e.read {
		_, verdict := e.p.everyActionDefault(e.ctx, e.f, e.s)
		e.read, e.permits = true, verdict == defaultPermits
	}
	if e.permits {
		return wire.DecisionOutcomePermitted
	}
	return outcome
}
