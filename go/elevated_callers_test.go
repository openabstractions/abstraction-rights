package rights

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
)

var elevatedEndpoints atomic.Int64

// boundTestPeer is this test process as a framed listener binds it.
func boundTestPeer(t *testing.T) (*identity.Peer, wire.Subject) {
	t.Helper()
	endpoint := listen.Endpoint(fmt.Sprintf("rights-elevated-test-%d-%d", os.Getpid(), elevatedEndpoints.Add(1)))
	if err := listen.CanEver(endpoint, listen.Program); err != nil {
		t.Skip("this platform cannot bind callers here: ", err)
	}
	l, err := listen.ListenFramed(endpoint, listen.Program)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	type accepted struct {
		peer *identity.Peer
		err  error
	}
	got := make(chan accepted, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			got <- accepted{err: err}
			return
		}
		defer conn.Close()
		call, err := listen.ReceiveFramed(ctx, conn, listen.Program, 1<<10)
		if err != nil {
			got <- accepted{err: err}
			return
		}
		defer call.Close()
		peer, err := call.Peer()
		call.Reply([]byte(`{}`))
		got <- accepted{peer: peer, err: err}
	}()
	if _, err := (listen.FrameClient{Endpoint: endpoint}).WithDefaults(5*time.Second, 1<<10).ExchangeFrameContext(ctx, []byte(`{}`)); err != nil {
		t.Logf("exchange: %v", err)
	}
	a := <-got
	if a.err != nil {
		t.Fatal(a.err)
	}
	s, err := client.SubjectFromPeer(a.peer)
	if err != nil {
		t.Fatal(err)
	}
	return a.peer, s
}

// RIGHTS-R27: the elevated-callers default permits every registered action
// for an elevated local peer of the account that binds the subject, with no
// rule written; the person's own rule decides first; a medium-integrity peer,
// a peer of another subject, another account and a switched-off default get
// not_granted; the script-host exclusion does not apply.
func TestElevatedCallersDefault(t *testing.T) {
	peer, s := boundTestPeer(t)
	elevated := true
	classify := func(*identity.Peer) bool { return elevated }
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, err := LoadDecisionPolicy(path, defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	everyProgramScripted := func(wire.Subject) bool { return true }
	if err := p.ConfigureDefaults(s.Account, append(testAccountDefaults(), ElevatedCallersDefault(classify)), everyProgramScripted); err != nil {
		t.Fatal(err)
	}
	if err := p.RegisterAction(decisionAction); err != nil {
		t.Fatal(err)
	}
	bound := WithBoundPeer(t.Context(), peer)
	if err := p.Require(t.Context(), peer, decisionAction, "anything"); err != nil {
		t.Fatal("an elevated caller was refused", err)
	}
	if got := p.DecideContext(bound, s, ActionQuestionAsk, ResourceAccount).Outcome; got != wire.DecisionOutcomePermitted {
		t.Fatal("an elevated script host was kept from the default", got)
	}
	explained := p.ExplainForContext(bound, s, decisionAction, "anything")
	if explained.Source == nil || *explained.Source != wire.DecisionSourceAccountDefault || explained.DefaultName != DefaultElevatedCallers {
		t.Fatal("explanation", explained)
	}
	if snapshot, err := p.OperatorSnapshot(); err != nil || len(snapshot.Rules) != 0 {
		t.Fatal("the default wrote a rule", snapshot, err)
	}
	if got := p.DecideContext(t.Context(), s, decisionAction, "anything").Outcome; got != wire.DecisionOutcomeNotGranted {
		t.Fatal("a decision without the bound peer was permitted", got)
	}
	other := wire.Subject{Account: s.Account, Program: filepath.Join(t.TempDir(), "other.exe")}
	if got := p.DecideContext(bound, other, decisionAction, "anything").Outcome; got != wire.DecisionOutcomeNotGranted {
		t.Fatal("the peer's elevation reached another program", got)
	}
	for _, account := range []string{"S-1-5-18", "S-1-5-21-1-2-3-500"} {
		if got := p.DecideContext(bound, wire.Subject{Account: account, Program: s.Program}, decisionAction, "anything").Outcome; got != wire.DecisionOutcomeNotGranted {
			t.Fatal("another account received the default", account, got)
		}
	}
	elevated = false
	if got := p.DecideContext(bound, s, decisionAction, "anything").Outcome; got != wire.DecisionOutcomeNotGranted {
		t.Fatal("a medium-integrity peer was permitted", got)
	}
	elevated = true
	if err := p.Set(s, decisionAction, "anything", false); err != nil {
		t.Fatal(err)
	}
	if got := p.DecideContext(bound, s, decisionAction, "anything").Outcome; got != wire.DecisionOutcomeDenied {
		t.Fatal("the person's Don't allow lost to the elevated default", got)
	}
	revision, _, err := p.DefaultsSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	off, err := p.SetDefault(revision, DefaultElevatedCallers, false, s, func() error { return nil })
	if err != nil || off.Outcome != wire.PolicyEditOutcomeApplied || off.Current == nil || off.Current.On || !off.Current.EveryResource || off.Current.Action != EveryActionName {
		t.Fatal(off, err)
	}
	if got := p.DecideContext(bound, s, decisionAction, "other").Outcome; got != wire.DecisionOutcomeNotGranted {
		t.Fatal("switched off, the elevated default still permitted", got)
	}
}

// RIGHTS-R27 on typed targets: the elevated default permits a typed target
// with no rule, and a typed Block still denies.
func TestElevatedCallersDefaultTyped(t *testing.T) {
	peer, s := boundTestPeer(t)
	p, err := LoadDecisionPolicyWithDefinitions(filepath.Join(t.TempDir(), "decisions.json"), []string{selectorUse, selectorCreate, selectorManage}, testSelectorCatalog(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ConfigureDefaults(s.Account, []AccountDefault{ElevatedCallersDefault(func(*identity.Peer) bool { return true })}, nil); err != nil {
		t.Fatal(err)
	}
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
	key := testSelection(selectorUse, "").Permission
	req := wire.CheckBatchRequest{CollectionAdmission: &key, Resources: []wire.ConcreteResource{{Permission: key, Target: testTarget("alpha")}, {Permission: key, Target: testTarget("beta")}}}
	bound := WithBoundPeer(t.Context(), peer)
	v := p.CheckBatchContext(bound, s, req)
	if v.Outcome != wire.BatchCheckOutcomeChecked || v.Outcomes[0] != wire.DecisionOutcomeDenied || v.Outcomes[1] != wire.DecisionOutcomePermitted {
		t.Fatal(v)
	}
	if v = p.CheckBatchContext(t.Context(), s, req); v.Outcomes[1] != wire.DecisionOutcomeNotGranted {
		t.Fatal("a typed target without the bound peer was permitted", v)
	}
	effect, err := p.Definitions.PreparePermissionEffect(s, []wire.PermissionSelection{testSelection(selectorUse, "beta")}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if consent := p.CheckPermissionEffectContext(bound, effect, ""); consent.Outcomes[0] != wire.DecisionOutcomePermitted {
		t.Fatal("consent admission asked an elevated caller", consent)
	}
}

// An every-action default must name no action and cover every resource; one
// that names an action, or a resource, is refused.
func TestEveryActionDefaultShape(t *testing.T) {
	p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), defaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []AccountDefault{
		{Name: "x", EveryAction: true, Action: ActionQuestionAsk, EveryResource: true},
		{Name: "x", EveryAction: true, Resource: ResourceAccount},
		{Name: "x", EveryResource: true},
	} {
		if err := p.ConfigureDefaults("acct", []AccountDefault{bad}, nil); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
