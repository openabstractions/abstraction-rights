package authorization

import (
	"context"
	"errors"
	"fmt"
	cas "github.com/openabstractions/abstraction-cas/go"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func liveOperator(t *testing.T, p *rights.DecisionPolicy, authorize AuthorizeOperator) (*Host, *client.Client, *client.Operator, string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("Program process/path evidence is not implemented on macOS")
	}
	endpoint := listen.Endpoint(fmt.Sprintf("rights-operator-%d-%d", os.Getpid(), serial.Add(1)))
	h, err := Listen(endpoint, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorize != nil {
		if err = h.EnableOperator(authorize); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background()) }()
	t.Cleanup(func() {
		h.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("operator failed to drain")
		}
	})
	return h, client.New(endpoint), client.NewOperator(endpoint), endpoint
}
func TestOperatorGrantRevokeScopeHistoryAndRestart(t *testing.T) {
	p, path := policy(t)
	subject := nativeSubject(t)
	var all, denied, outage atomic.Bool
	authorize := func(_ context.Context, peer *identity.Peer) error {
		if outage.Load() {
			return errors.New("policy unavailable")
		}
		got, err := client.SubjectFromPeer(peer)
		if err != nil {
			return err
		}
		if denied.Load() || (!all.Load() && got != subject) {
			return ErrOperatorForbidden
		}
		return nil
	}
	h, decisions, op, endpoint := liveOperator(t, p, authorize)
	page, err := op.ListPolicyContext(context.Background(), "", 1)
	if err != nil || !page.Complete || len(page.Rules) != 0 {
		t.Fatal(page, err)
	}
	originalRevision := page.Revision
	rule := wire.PolicyRule{Subject: subject, Action: action, Resource: "x", Permit: true}
	applied, err := op.SetRuleContext(context.Background(), page.Revision, rule)
	if err != nil || applied.Outcome != "applied" {
		t.Fatal(applied, err)
	}
	decision, err := decisions.DecideContext(context.Background(), action, "x")
	if err != nil || decision.Outcome != "permitted" {
		t.Fatal(decision, err)
	}
	replay, err := op.SetRuleContext(context.Background(), originalRevision, rule)
	if err != nil || replay.Outcome != "conflict" || replay.Revision != applied.Revision || replay.Current == nil || !replay.Current.Permit {
		t.Fatal(replay, err)
	}
	rule.Resource = "y"
	rule.Permit = false
	second, err := op.SetRuleContext(context.Background(), applied.Revision, rule)
	if err != nil || second.Outcome != "applied" {
		t.Fatal(second, err)
	}
	page, err = op.ListPolicyContext(context.Background(), "", 1)
	if err != nil || page.Next == "" {
		t.Fatal(page, err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "ordinary.exe")
	if err = os.WriteFile(copied, data, 0700); err != nil {
		t.Fatal(err)
	}
	child := func(want string) {
		t.Helper()
		cmd := exec.Command(copied, "-test.run=^TestOperatorCallerProcess$")
		cmd.Env = append(os.Environ(), "OA_RIGHTS_OPERATOR="+endpoint, "OA_RIGHTS_CURSOR="+page.Next, "OA_RIGHTS_REVISION="+page.Revision, "OA_RIGHTS_WANT="+want)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v %s", err, out)
		}
	}
	child("forbidden")
	all.Store(true)
	child("gap")
	all.Store(false)
	denied.Store(true)
	refused, err := op.RevokeRuleContext(context.Background(), page.Revision, subject, action, "x")
	if err != nil || refused.Outcome != "forbidden" {
		t.Fatal(refused, err)
	}
	denied.Store(false)
	outage.Store(true)
	unavailable, err := op.ListPolicyContext(context.Background(), "", 1)
	if err != nil || unavailable.Outcome != "unavailable" {
		t.Fatal(unavailable, err)
	}
	outage.Store(false)
	if d, _ := decisions.DecideContext(context.Background(), action, "x"); d.Outcome != "permitted" {
		t.Fatal("denied operator changed rule", d)
	}
	revoked, err := op.RevokeRuleContext(context.Background(), page.Revision, subject, action, "x")
	if err != nil || revoked.Outcome != "applied" || revoked.Current != nil {
		t.Fatal(revoked, err)
	}
	if d, _ := decisions.DecideContext(context.Background(), action, "x"); d.Outcome != "not_granted" {
		t.Fatal("revocation stale", d)
	}
	gap, err := op.ListPolicyContext(context.Background(), page.Next, 1)
	if err != nil || gap.Outcome != "gap" {
		t.Fatal(gap, err)
	}
	h.Close()
	reopened, err := rights.LoadDecisionPolicy(path, []string{action})
	if err != nil {
		t.Fatal(err)
	}
	_, _, fresh, _ := liveOperator(t, reopened, authorize)
	restarted, err := fresh.ListPolicyContext(context.Background(), "", 64)
	if err != nil || restarted.Revision != revoked.Revision {
		t.Fatal("durable revision changed", restarted, err)
	}
	gap, err = fresh.ListPolicyContext(context.Background(), page.Next, 1)
	if err != nil || gap.Outcome != "gap" {
		t.Fatal(gap, err)
	}
}
func TestOperatorCallerProcess(t *testing.T) {
	endpoint := os.Getenv("OA_RIGHTS_OPERATOR")
	if endpoint == "" {
		return
	}
	op := client.NewOperator(endpoint)
	page, err := op.ListPolicyContext(context.Background(), os.Getenv("OA_RIGHTS_CURSOR"), 1)
	if err != nil || page.Outcome != os.Getenv("OA_RIGHTS_WANT") {
		os.Exit(3)
	}
	if page.Outcome == "forbidden" {
		r, err := op.SetRuleContext(context.Background(), os.Getenv("OA_RIGHTS_REVISION"), wire.PolicyRule{Subject: nativeSubject(t), Action: action, Resource: "x", Permit: true})
		if err != nil || r.Outcome != "forbidden" {
			os.Exit(4)
		}
	}
	os.Exit(0)
}
func TestOperatorCancelledEditAndWireBounds(t *testing.T) {
	p, path := policy(t)
	subject := nativeSubject(t)
	entered := make(chan struct{}, 1)
	h, _, op, endpoint := liveOperator(t, p, func(context.Context, *identity.Peer) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		return nil
	})
	initial, err := op.ListPolicyContext(context.Background(), "", 1)
	if err != nil {
		t.Fatal(err)
	}
	for len(entered) > 0 {
		<-entered
	}
	locked, release := make(chan struct{}), make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- cas.ChangeLimit(path, rights.MaxDecisionBytes, func(data []byte) ([]byte, error) { close(locked); <-release; return data, nil })
	}()
	<-locked
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := op.SetRuleContext(ctx, initial.Revision, wire.PolicyRule{Subject: subject, Action: action, Resource: "x", Permit: true})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("edit not admitted")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Error("cancel did not stop wait")
	}
	close(release)
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(h.slots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("cancel retained call")
		}
		runtime.Gosched()
	}
	if d := p.Decide(subject, action, "x"); d.Outcome != "not_granted" {
		t.Fatal("canceled wait granted", d)
	}
	wireClient := wire.NewAuthorizationOperatorClient(listen.FrameClient{Endpoint: endpoint, Timeout: time.Second, MaxFrame: MaxFrameBytes})
	for _, n := range []int64{0, 65} {
		v, err := wireClient.ListPolicy("", n)
		if err != nil || v.Outcome != "invalid" {
			t.Fatal(v, err)
		}
	}
	v, err := wireClient.ListPolicy(strings.Repeat("x", 257), 1)
	if err != nil || v.Outcome != "invalid" {
		t.Fatal(v, err)
	}
	result, err := wireClient.SetRule(strings.Repeat("x", 129), wire.PolicyRule{Subject: subject, Action: action, Resource: "x", Permit: true})
	if err != nil || result.Outcome != "invalid" {
		t.Fatal(result, err)
	}
}
func TestOperatorUnconfiguredRefuses(t *testing.T) {
	p, _ := policy(t)
	h, _, op, _ := liveOperator(t, p, nil)
	v, err := op.ListPolicyContext(context.Background(), "", 1)
	if err != nil || v.Outcome != "forbidden" || h.OperatorAvailable() {
		t.Fatal(v, err)
	}
}

type measuredPolicyTransport struct {
	listen.FrameClient
	replyBytes int
}

func (m *measuredPolicyTransport) ExchangeFrame(frame []byte) ([]byte, error) {
	reply, err := m.FrameClient.ExchangeFrame(frame)
	m.replyBytes = len(reply)
	return reply, err
}
func TestOperatorPolicyCatalogueAndLargeRulesStayBounded(t *testing.T) {
	catalog := make([]string, 64)
	for i := range catalog {
		catalog[i] = fmt.Sprintf("%03d", i) + strings.Repeat("a", 125)
	}
	p, err := rights.LoadDecisionPolicy(filepath.Join(t.TempDir(), "policy.json"), catalog)
	if err != nil {
		t.Fatal(err)
	}
	subject := nativeSubject(t)
	subject.Program = filepath.Join(filepath.VolumeName(subject.Program)+string(os.PathSeparator), strings.Repeat("p", 3900))
	for i := 0; i < 64; i++ {
		if err = p.Set(subject, catalog[0], fmt.Sprintf("%03d", i)+strings.Repeat("r", 1021), true); err != nil {
			t.Fatal(err)
		}
	}
	_, _, _, endpoint := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	transport := &measuredPolicyTransport{FrameClient: listen.FrameClient{Endpoint: endpoint, Timeout: 5 * time.Second, MaxFrame: MaxFrameBytes}}
	c := wire.NewAuthorizationOperatorClient(transport)
	cursor := ""
	seen := 0
	for pages := 0; pages < 4; pages++ {
		page, err := c.ListPolicy(cursor, 64)
		if err != nil || page.Outcome != "page" || len(page.Catalog) != 64 || len(page.Rules) == 0 || len(page.Rules) > 64 || transport.replyBytes > 256<<10 {
			t.Fatal("policy budget", page.Outcome, len(page.Rules), transport.replyBytes, err)
		}
		seen += len(page.Rules)
		if page.Complete {
			if seen != 64 {
				t.Fatal("lost rules", seen)
			}
			return
		}
		cursor = page.Next
	}
	t.Fatal("bounded traversal did not finish")
}
