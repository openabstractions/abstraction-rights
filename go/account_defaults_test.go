package rights

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// defaultSeed is a catalogue holding every action the runtime's defaults name.
var defaultSeed = []string{ActionApplicationRegisterSelf, ActionApplicationAnnounce, ActionQuestionAsk, testNotifyAction, ActionJobSubmit}

// testNotifyAction stands in for the notify default's action, which the
// facade grants define; rights tests name no service above them.
const testNotifyAction = "example.notices/notice.post"

// testAccountDefaults is the runtime's five defaults in shape
// (grants.RuntimeAccountDefaults).
func testAccountDefaults() []AccountDefault {
	return []AccountDefault{
		{Name: DefaultRegister, Action: ActionApplicationRegisterSelf, Resource: ResourceAccount},
		{Name: DefaultAsk, Action: ActionQuestionAsk, Resource: ResourceAccount},
		{Name: DefaultAnnounce, Action: ActionApplicationAnnounce, EveryResource: true},
		{Name: DefaultNotify, Action: testNotifyAction, Resource: ResourceAccount},
		{Name: DefaultDownload, Action: ActionJobSubmit, Resource: ResourceDownloadJobs},
	}
}

// defaultsPolicy loads a policy with the runtime's defaults for subject(t)'s
// account, excluding script.
func defaultsPolicy(t *testing.T, path string, script wire.Subject) *DecisionPolicy {
	t.Helper()
	p, err := LoadDecisionPolicy(path, defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	excluded := func(s wire.Subject) bool { return identity.SameSubjectProgram(s.Program, script.Program) }
	if err := p.ConfigureDefaults(subject(t).Account, testAccountDefaults(), excluded); err != nil {
		t.Fatal(err)
	}
	return p
}

func scriptHost(t *testing.T) wire.Subject {
	return wire.Subject{Account: subject(t).Account, Program: filepath.Join(t.TempDir(), "python.exe")}
}

func decide(t *testing.T, p *DecisionPolicy, s wire.Subject, action, resource string) wire.DecisionOutcome {
	t.Helper()
	return p.Decide(s, action, resource).Outcome
}

// RIGHTS-R22: each default permits a program of the account with no rule of
// its own, on its exact resource or every resource; other resources, other
// accounts and a script host get nothing.
func TestAccountDefaultsPermitAProgramWithoutRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	script := scriptHost(t)
	p := defaultsPolicy(t, path, script)
	s := subject(t)
	for _, c := range []struct{ action, resource string }{
		{ActionApplicationRegisterSelf, ResourceAccount},
		{ActionQuestionAsk, ResourceAccount},
		{ActionApplicationAnnounce, "app:alpha"},
		{ActionApplicationAnnounce, "app:beta"},
		{testNotifyAction, ResourceAccount},
		{ActionJobSubmit, ResourceDownloadJobs},
	} {
		if got := decide(t, p, s, c.action, c.resource); got != wire.DecisionOutcomePermitted {
			t.Errorf("%s on %s = %s, want permitted", c.action, c.resource, got)
		}
		if got := decide(t, p, script, c.action, c.resource); got != wire.DecisionOutcomeNotGranted {
			t.Errorf("script host %s on %s = %s, want not_granted", c.action, c.resource, got)
		}
		remote := wire.Subject{Account: "mapped-remote-namespace", Program: s.Program}
		if got := decide(t, p, remote, c.action, c.resource); got != wire.DecisionOutcomeNotGranted {
			t.Errorf("remote %s on %s = %s, want not_granted", c.action, c.resource, got)
		}
	}
	for _, c := range []struct{ action, resource string }{
		{ActionJobSubmit, "job:inference"},
		{ActionJobSubmit, "abstraction.job/acceptance@1"},
		{ActionQuestionAsk, "apps"},
	} {
		if got := decide(t, p, s, c.action, c.resource); got != wire.DecisionOutcomeNotGranted {
			t.Errorf("%s on %s = %s, want not_granted", c.action, c.resource, got)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a default wrote the policy file", err)
	}
	unconfigured, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	if got := decide(t, unconfigured, s, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("a policy with no configured defaults permitted", got)
	}
}

// RIGHTS-R22: the program's own live rule decides before a default: a Block
// refuses that program alone, a permit permits, and removing the rule returns
// it to the default. An expired rule counts as none.
func TestAccountDefaultsYieldToTheProgramsOwnRule(t *testing.T) {
	p := defaultsPolicy(t, filepath.Join(t.TempDir(), "decisions.json"), scriptHost(t))
	s := subject(t)
	other := wire.Subject{Account: s.Account, Program: filepath.Join(t.TempDir(), "other.exe")}
	if err := p.Set(s, ActionJobSubmit, ResourceDownloadJobs, false); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, p, s, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomeDenied {
		t.Fatal("Block did not win over the default", got)
	}
	if got := decide(t, p, other, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomePermitted {
		t.Fatal("one program's Block refused another", got)
	}
	if err := p.Revoke(s, ActionJobSubmit, ResourceDownloadJobs); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, p, s, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomePermitted {
		t.Fatal("removing the Block did not return to the default", got)
	}
	// A per-app permit on a script host permits: the exclusion covers defaults only.
	script := scriptHost(t)
	p = defaultsPolicy(t, filepath.Join(t.TempDir(), "decisions.json"), script)
	if err := p.Set(script, ActionQuestionAsk, ResourceAccount, true); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, p, script, ActionQuestionAsk, ResourceAccount); got != wire.DecisionOutcomePermitted {
		t.Fatal("a script host's own permit was ignored", got)
	}
	// An expired Block decides nothing, and the default applies again.
	now := time.Now().UTC()
	p.Clock = func() time.Time { return now }
	snapshot, err := p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	deny := false
	edit, err := p.ChangeRule(snapshot.Revision, s, ActionApplicationAnnounce, "app:alpha", RuleEdit{Permit: &deny, By: s, TTL: time.Second}, func() error { return nil })
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	if got := decide(t, p, s, ActionApplicationAnnounce, "app:alpha"); got != wire.DecisionOutcomeDenied {
		t.Fatal("live timed Block", got)
	}
	now = now.Add(2 * time.Second)
	if got := decide(t, p, s, ActionApplicationAnnounce, "app:alpha"); got != wire.DecisionOutcomePermitted {
		t.Fatal("expired Block still refused", got)
	}
}

// RIGHTS-R22, RIGHTS-O13: a switch turned off refuses at the next fresh
// decision and survives reload; turned on it permits again. Edits are
// conditional, record their setter, and change the revision; a switch already
// in the requested state writes nothing.
func TestAccountDefaultSwitches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	script := scriptHost(t)
	p := defaultsPolicy(t, path, script)
	s := subject(t)
	authorize := func() error { return nil }
	revision, defaults, err := p.DefaultsSnapshot(t.Context())
	if err != nil || len(defaults) != 5 {
		t.Fatal(defaults, err)
	}
	for i, d := range defaults {
		if !d.On || d.SetBy != nil || d.SetAt != "" || i > 0 && defaults[i-1].Name >= d.Name {
			t.Fatal("fresh defaults are not all on and sorted", defaults)
		}
	}
	same, err := p.SetDefault(revision, DefaultDownload, true, s, authorize)
	if err != nil || same.Outcome != wire.PolicyEditOutcomeApplied || same.Revision != revision || same.Current == nil || !same.Current.On {
		t.Fatal(same, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a no-op switch edit wrote", err)
	}
	off, err := p.SetDefault(revision, DefaultDownload, false, s, authorize)
	if err != nil || off.Outcome != wire.PolicyEditOutcomeApplied || off.Revision == revision || off.Current == nil || off.Current.On || off.Current.SetBy == nil || off.Current.SetAt == "" {
		t.Fatal(off, err)
	}
	if got := decide(t, p, s, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("switched-off default permitted", got)
	}
	if got := decide(t, p, s, ActionQuestionAsk, ResourceAccount); got != wire.DecisionOutcomePermitted {
		t.Fatal("turning one default off turned another off", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(raw, []byte(DecisionProfile)) || !bytes.Contains(raw, []byte(`"default_switches"`)) {
		t.Fatal("switch state not stored in the current profile", string(raw), err)
	}
	stale, err := p.SetDefault(revision, DefaultDownload, true, s, authorize)
	if err != nil || stale.Outcome != wire.PolicyEditOutcomeConflict || stale.Revision != off.Revision || stale.Current == nil || stale.Current.On {
		t.Fatal("stale switch edit", stale, err)
	}
	if bad, err := p.SetDefault(off.Revision, "everything", true, s, authorize); err != nil || bad.Outcome != wire.PolicyEditOutcomeInvalid {
		t.Fatal("unconfigured switch", bad, err)
	}
	reloaded := defaultsPolicy(t, path, script)
	if got := decide(t, reloaded, s, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("switch did not survive reload", got)
	}
	on, err := reloaded.SetDefault(off.Revision, DefaultDownload, true, s, authorize)
	if err != nil || on.Outcome != wire.PolicyEditOutcomeApplied || !on.Current.On || on.Revision == off.Revision {
		t.Fatal(on, err)
	}
	if got := decide(t, reloaded, s, ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomePermitted {
		t.Fatal("switched-on default refused", got)
	}
	if refused, err := reloaded.SetDefault(on.Revision, DefaultDownload, false, s, func() error { return errors.New("operator gone") }); err == nil || refused.Outcome != wire.PolicyEditOutcomeUnavailable {
		t.Fatal("in-lock authorization not rechecked", refused, err)
	}
}

// RIGHTS-R8, RIGHTS-R22: an outage is unavailable before any default.
func TestAccountDefaultsNeverPermitDuringAnOutage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	p := defaultsPolicy(t, path, scriptHost(t))
	p.StateRequired = true
	if got := decide(t, p, subject(t), ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomeUnavailable {
		t.Fatal("missing required state", got)
	}
	if err := os.WriteFile(path, []byte(`{"bad":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, p, subject(t), ActionJobSubmit, ResourceDownloadJobs); got != wire.DecisionOutcomeUnavailable {
		t.Fatal("malformed state", got)
	}
}

// RIGHTS-R5: switch state belongs to rights-decisions@7; an older profile
// carrying it is refused, and a @6 file without it stays readable.
func TestDefaultSwitchesRequireTheCurrentProfile(t *testing.T) {
	s := subject(t)
	stored := defaultSwitch{Name: DefaultDownload, On: false, SetBy: s, SetAt: stamp(time.Now())}
	for _, c := range []struct {
		profile string
		ok      bool
	}{{typedDecisionProfile, false}, {DecisionProfile, true}} {
		data, err := json.Marshal(decisionFile{Profile: c.profile, DefaultSwitches: []defaultSwitch{stored}})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "decisions.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = LoadDecisionPolicy(path, defaultSeed)
		if (err == nil) != c.ok {
			t.Fatal(c.profile, err)
		}
	}
	data, err := json.Marshal(decisionFile{Profile: typedDecisionProfile})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "decisions.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecisionPolicy(path, defaultSeed); err != nil {
		t.Fatal("a @6 file stopped loading", err)
	}
}

// ConfigureDefaults refuses a malformed table.
func TestConfigureDefaultsRefusesMalformedDefaults(t *testing.T) {
	p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]AccountDefault{
		{{Name: "Upper", Action: ActionQuestionAsk, Resource: ResourceAccount}},
		{{Name: "a", Action: ActionQuestionAsk, Resource: ResourceAccount}, {Name: "a", Action: ActionJobSubmit, Resource: ResourceDownloadJobs}},
		{{Name: "a", Action: ActionQuestionAsk}},
		{{Name: "a", Action: ActionQuestionAsk, Resource: ResourceAccount, EveryResource: true}},
		{{Name: "a", Action: "no-slash", Resource: ResourceAccount}},
	} {
		if err := p.ConfigureDefaults("acct", bad, nil); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
