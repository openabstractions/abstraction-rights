package gate

import (
	"context"
	"errors"
	"fmt"
	"github.com/openabstractions/abstraction-rights/go/internal/personfolders"
	"os"
	"os/user"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

func permit(context.Context, *identity.Peer, string, string) error { return nil }

// local is the gate Local returns, for a named account.
func local(namespace, owner string) Gate {
	g, err := For(namespace, account(owner))
	if err != nil {
		panic(err)
	}
	return g
}

func TestForNeedsOneNamespaceAndAGate(t *testing.T) {
	for _, namespace := range []string{"", "abstraction.router/route"} {
		if _, err := For(namespace, permit); err == nil {
			t.Fatalf("For(%q) accepted a namespace", namespace)
		}
	}
	if _, err := For("abstraction.router", nil); err == nil {
		t.Fatal("For designated a nil gate")
	}
}

// TestForRefusesEveryActionOutsideItsNamespace: a gate that permits anything,
// once designated for a namespace, refuses every action outside it and never
// asks the gate for one, and still decides the namespace's own actions
// (RIGHTS-A7).
func TestForRefusesEveryActionOutsideItsNamespace(t *testing.T) {
	asked := 0
	g, err := For("abstraction.router", func(context.Context, *identity.Peer, string, string) error { asked++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"abstraction.resource/hold", "abstraction.routerx/route", "abstraction.router", "app.comfyui/workflow.run", ""} {
		err := g.Check(context.Background(), &identity.Peer{}, action, "account")
		if err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatalf("a permit-all gate designated for the router decided %q as %v, want a refusal", action, err)
		}
	}
	if asked != 0 {
		t.Fatalf("the designated gate was asked %d times for actions outside its namespace", asked)
	}
	if err := g.Check(context.Background(), &identity.Peer{}, "abstraction.router/route", "account"); err != nil || asked != 1 {
		t.Fatalf("the router's own action read %v after %d asks", err, asked)
	}
}

// TestNilGateIsUnavailable: a service nobody installed a gate on decides
// nothing, and the operation reads unavailable (ARCHITECTURE.md, RIGHTS-R26).
func TestNilGateIsUnavailable(t *testing.T) {
	var g Gate
	err := g.Check(context.Background(), &identity.Peer{}, "abstraction.router/route", "account")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a nil gate decided %v", err)
	}
}

// TestCheckRefusesWhatItCannotEvaluate: an unbound caller and a context that
// ends before or during the decision read unavailable, whatever the gate
// would say (RIGHTS-R26).
func TestCheckRefusesWhatItCannotEvaluate(t *testing.T) {
	asked := 0
	counting := Gate(func(context.Context, *identity.Peer, string, string) error { asked++; return nil })
	if err := counting.Check(context.Background(), nil, "a.b/c", "r"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unbound caller decided %v", err)
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := counting.Check(ended, &identity.Peer{}, "a.b/c", "r"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("an ended context decided %v", err)
	}
	if asked != 0 {
		t.Fatalf("the gate was asked %d times for decisions that could not be evaluated", asked)
	}
	during, stop := context.WithCancel(context.Background())
	late := Gate(func(context.Context, *identity.Peer, string, string) error { stop(); return nil })
	if err := late.Check(during, &identity.Peer{}, "a.b/c", "r"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a permit after the context ended decided %v", err)
	}
}

// TestCheckKeepsTheGatesDecision: a permit stays a permit, a refusal stays a
// refusal, and an unavailable decision stays unavailable.
func TestCheckKeepsTheGatesDecision(t *testing.T) {
	peer := &identity.Peer{}
	if err := Gate(permit).Check(context.Background(), peer, "a.b/c", "r"); err != nil {
		t.Fatalf("a permit read %v", err)
	}
	refused := errors.New("no rule")
	err := Gate(func(context.Context, *identity.Peer, string, string) error { return refused }).Check(context.Background(), peer, "a.b/c", "r")
	if !errors.Is(err, refused) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("a refusal read %v", err)
	}
	err = Gate(func(context.Context, *identity.Peer, string, string) error {
		return fmt.Errorf("%w: outage", ErrUnavailable)
	}).Check(context.Background(), peer, "a.b/c", "r")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an outage read %v", err)
	}
}

func TestLocalNeedsOneNamespace(t *testing.T) {
	for _, namespace := range []string{"", "abstraction.router/route"} {
		if _, err := Local(namespace); err == nil {
			t.Fatalf("Local(%q) accepted a namespace", namespace)
		}
	}
	if _, err := Local("abstraction.router"); err != nil {
		t.Fatal(err)
	}
}

// TestLocalIsDesignatedForItsNamespace: the local gate refuses every action
// outside its own namespace, including one whose name only starts with it
// (RIGHTS-A7).
func TestLocalIsDesignatedForItsNamespace(t *testing.T) {
	g := local("abstraction.router", "any")
	for _, action := range []string{"abstraction.resource/hold", "abstraction.routerx/route", "abstraction.router", "app.comfyui/workflow.run"} {
		err := g.Check(context.Background(), &identity.Peer{}, action, "account")
		if err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatalf("the router's local gate decided %s as %v, want a refusal", action, err)
		}
	}
}

// TestLocalCannotNameAnUnprovenCaller: a caller whose account the service
// cannot name reads unavailable, never a permit (RIGHTS-R26).
func TestLocalCannotNameAnUnprovenCaller(t *testing.T) {
	err := local("abstraction.router", "any").Check(context.Background(), &identity.Peer{}, "abstraction.router/route", "account")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unproven caller decided %v", err)
	}
}

// TestLocalPermitsOnlyTheServiceAccount: a caller bound by the kernel under
// the service's own account is permitted; the same caller checked against
// another account is refused.
func TestLocalPermitsOnlyTheServiceAccount(t *testing.T) {
	peer := boundSelf(t)
	owner, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if err := local("abstraction.router", owner.Uid).Check(context.Background(), peer, "abstraction.router/route", "account"); err != nil {
		t.Fatalf("the service's own account was refused: %v", err)
	}
	err = local("abstraction.router", owner.Uid+"-other").Check(context.Background(), peer, "abstraction.router/route", "account")
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("another account decided %v, want a refusal", err)
	}
}

// endpoints numbers this process's test endpoints.
var endpoints atomic.Int64

// boundSelf is this test process as a framed listener binds it.
func boundSelf(t *testing.T) *identity.Peer {
	t.Helper()
	endpoint := listen.Endpoint(fmt.Sprintf("rights-gate-test-%d-%d", os.Getpid(), endpoints.Add(1)))
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
	return a.peer
}

// TestMain confines per-user folders to the canonical owned test fixture.
func TestMain(m *testing.M) { os.Exit(personfolders.Main(m)) }
