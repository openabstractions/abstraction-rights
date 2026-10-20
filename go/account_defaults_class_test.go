package rights

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

const testMessageAction = "example.facade/application.message"

// RIGHTS-R22: a default configured Off stays off after a fresh install until
// an operator turns it on; a host class permits only the targets it covers;
// the program's own rule still decides first; an existing default without Off
// or Covers keeps its revision and behaviour.
func TestAccountDefaultOffClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	s := subject(t)
	agent := wire.Subject{Account: s.Account, Program: filepath.Join(t.TempDir(), "agent.exe")}
	covers := func(_ context.Context, subject wire.Subject, resource string) bool {
		return identity.SameSubjectProgram(subject.Program, agent.Program) && resource == "app:peer"
	}
	load := func() *DecisionPolicy {
		p, err := LoadDecisionPolicy(path, append([]string{testMessageAction}, defaultSeed...))
		if err != nil {
			t.Fatal(err)
		}
		defaults := append(testAccountDefaults(), AccountDefault{Name: "agent-messages", Action: testMessageAction, EveryResource: true, Off: true, Covers: covers})
		if err := p.ConfigureDefaults(s.Account, defaults, nil); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := load()
	revision, defaults, err := p.DefaultsSnapshot(t.Context())
	if err != nil || len(defaults) != 6 {
		t.Fatal(defaults, err)
	}
	for _, d := range defaults {
		if d.Name == "agent-messages" && (d.On || !d.EveryResource || d.SetBy != nil) || d.Name != "agent-messages" && !d.On {
			t.Fatal("fresh switch states", defaults)
		}
	}
	if got := decide(t, p, agent, testMessageAction, "app:peer"); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("an Off default permitted before it was turned on", got)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an Off default wrote the policy file", err)
	}
	on, err := p.SetDefault(revision, "agent-messages", true, s, func() error { return nil })
	if err != nil || on.Outcome != wire.PolicyEditOutcomeApplied || on.Current == nil || !on.Current.On || on.Revision == revision {
		t.Fatal(on, err)
	}
	if got := decide(t, p, agent, testMessageAction, "app:peer"); got != wire.DecisionOutcomePermitted {
		t.Fatal("a covered target was not permitted", got)
	}
	explained := p.legacyOperationExplained(t.Context(), mustDecode(t, p), on.Revision, agent, wire.LegacyOperationRequest{LegacyAction: testMessageAction, LegacyResource: "app:peer"}, p.now())
	if explained.Source == nil || *explained.Source != wire.DecisionSourceAccountDefault || explained.DefaultName != "agent-messages" {
		t.Fatal("explanation", explained)
	}
	for _, c := range []struct {
		subject  wire.Subject
		resource string
	}{{agent, "app:other"}, {s, "app:peer"}, {wire.Subject{Account: "mapped-remote-namespace", Program: agent.Program}, "app:peer"}} {
		if got := decide(t, p, c.subject, testMessageAction, c.resource); got != wire.DecisionOutcomeNotGranted {
			t.Errorf("%s on %s = %s outside the class", c.subject.Program, c.resource, got)
		}
	}
	if err := p.Set(agent, testMessageAction, "app:peer", false); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, p, agent, testMessageAction, "app:peer"); got != wire.DecisionOutcomeDenied {
		t.Fatal("the program's own Don't allow lost to the class default", got)
	}
	if err := p.Revoke(agent, testMessageAction, "app:peer"); err != nil {
		t.Fatal(err)
	}
	reloaded := load()
	if got := decide(t, reloaded, agent, testMessageAction, "app:peer"); got != wire.DecisionOutcomePermitted {
		t.Fatal("the turned switch did not survive reload", got)
	}
	_, current, err := reloaded.DefaultsSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := ""
	for _, d := range current {
		if d.Name == "agent-messages" {
			now = map[bool]string{true: "on", false: "off"}[d.On]
		}
	}
	if now != "on" {
		t.Fatal("snapshot after reload", current)
	}
	revision, _, _ = reloaded.DefaultsSnapshot(t.Context())
	off, err := reloaded.SetDefault(revision, "agent-messages", false, s, func() error { return nil })
	if err != nil || off.Outcome != wire.PolicyEditOutcomeApplied || off.Current.On {
		t.Fatal(off, err)
	}
	if got := decide(t, reloaded, agent, testMessageAction, "app:peer"); got != wire.DecisionOutcomeNotGranted {
		t.Fatal("switched off, the class default still permitted", got)
	}
}

// An existing default with neither Off nor Covers keeps the configuration
// digest it had before the two fields existed.
func TestAccountDefaultDigestUnchangedWithoutOffOrCovers(t *testing.T) {
	p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ConfigureDefaults("acct", testAccountDefaults(), nil); err != nil {
		t.Fatal(err)
	}
	// The digest as computed before Off and Covers existed.
	type earlier struct {
		Name          string
		Action        string
		Resource      string
		EveryResource bool
	}
	var shaped []earlier
	for _, d := range testAccountDefaults() {
		shaped = append(shaped, earlier{d.Name, d.Action, d.Resource, d.EveryResource})
	}
	data, err := json.Marshal(struct {
		Account  string
		Defaults []earlier
	}{"acct", shaped})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := p.defaultsDigest(); got != hex.EncodeToString(sum[:]) {
		t.Fatal("existing defaults changed their digest", got)
	}
}

func mustDecode(t *testing.T, p *DecisionPolicy) decisionFile {
	t.Helper()
	f, _, err := p.readDecisionContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return f
}
