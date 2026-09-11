package rights

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	asks "github.com/openabstractions/abstraction-asks/go"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	watch "github.com/openabstractions/abstraction-watch/go"
)

type harness struct {
	s      *Service
	app    *Client
	tool   *Client
	person *asks.Client
}

func endpoint(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		short, err := os.MkdirTemp("/tmp", "rights-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(short) })
		dir = short
	}
	if runtime.GOOS != "windows" {
		return filepath.Join(dir, name)
	}
	return fmt.Sprintf(`\\.\pipe\%s-test-%d-%s`, name, os.Getpid(), t.Name())
}

func start(t *testing.T) harness {
	t.Helper()
	if runtime.GOOS == "darwin" {
		if err := identity.CanEver(listen.Program); err != nil {
			t.Skipf("UNPROVEN: successful Program-bound service case on current macOS socket transport; requires native transport proof: %v", err)
		}
	}
	dir := t.TempDir()
	asksDir := filepath.Join(dir, "asks")
	asksAt := endpoint(t, asksDir, "asks")
	a, err := asks.Start(asksAt, asksDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	at := endpoint(t, dir, "rights")
	s, err := Start(at, dir, asksAt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	admin, _ := os.ReadFile(filepath.Join(dir, "admin.secret"))
	personAdmin, _ := os.ReadFile(filepath.Join(asksDir, "admin.secret"))
	return harness{s: s, app: &Client{Endpoint: at}, tool: &Client{Endpoint: at, Admin: string(admin)},
		person: &asks.Client{Endpoint: asksAt, Admin: string(personAdmin)}}
}

func awaitQuestion(t *testing.T, person *asks.Client) asks.Record {
	t.Helper()
	sub := watch.Poll(func() ([]asks.Record, string, error) {
		rs, err := person.Pending()
		return rs, fmt.Sprint(len(rs)), err
	}, 10*time.Millisecond, 0)
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		n, err := sub.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(n.Now) > 0 {
			return n.Now[0]
		}
	}
}

func registerApproved(t *testing.T, h harness, name string) string {
	t.Helper()
	secret := make(chan string, 1)
	fail := make(chan error, 1)
	go func() {
		s, err := h.app.Register(name, RightAwake)
		if err != nil {
			fail <- err
			return
		}
		secret <- s
	}()
	q := awaitQuestion(t, h.person)
	if q.Asker != name || q.Key != "rights.register" {
		t.Fatalf("the question asked was %+v", q)
	}
	if identity.Ceiling().Bindable && !q.Via.Bound {
		t.Fatalf("this machine can bind but the asker is not bound: %s", q.Via.Why)
	}
	if _, err := h.person.Answer(q.ID, "allow"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-secret:
		return s
	case err := <-fail:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("register never returned")
	}
	return ""
}

func TestRegisterAskHoldRevoke(t *testing.T) {
	h := start(t)
	app, tool := h.app, h.tool
	released := make(chan struct{}, 4)
	h.s.awake = func(who, why string) (func(), error) { return func() { released <- struct{}{} }, nil }

	secret := registerApproved(t, h, "demo")
	apps, _ := tool.Apps()
	if len(apps) != 1 || apps[0].Name != "demo" || len(apps[0].Rights) != 1 {
		t.Fatalf("apps = %+v", apps)
	}

	if _, _, err := app.Ask("wrong", RightAwake); err == nil || err.Error() != ErrBadSecret.Error() {
		t.Fatalf("wrong secret: %v", err)
	}
	if _, _, err := app.Ask(secret, "fly"); err == nil {
		t.Fatal("a right nobody granted was issued")
	}
	token, expires, err := app.Ask(secret, RightAwake)
	if err != nil || time.Until(expires) < 50*time.Minute {
		t.Fatalf("ask: %v %v", err, expires)
	}
	if a, right, err := app.Check(token); err != nil || a.Name != "demo" || right != RightAwake {
		t.Fatalf("check: %v %v %v", a, right, err)
	}

	lease, err := app.Hold(token, "test")
	if err != nil {
		t.Fatal(err)
	}
	holds, _ := tool.Holds()
	if len(holds) != 1 || holds[0].Why != "test" {
		t.Fatalf("holds = %+v", holds)
	}
	if err := tool.Revoke("demo", RightAwake); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lease.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("revoke did not drop the hold")
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the platform hold was not released")
	}
	if holds, _ := tool.Holds(); len(holds) != 0 {
		t.Fatalf("holds after revoke = %+v", holds)
	}
	if _, _, err := app.Check(token); err == nil {
		t.Fatal("a revoked token still checks")
	}
	if _, _, err := app.Ask(secret, RightAwake); err == nil {
		t.Fatal("a revoked right was issued again")
	}

	if err := tool.Grant("demo", RightAwake); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.Ask(secret, RightAwake); err != nil {
		t.Fatalf("after grant: %v", err)
	}
}

func TestPolicySurvivesRestart(t *testing.T) {
	h := start(t)
	secret := registerApproved(t, h, "durable")
	h.s.Close()

	again, err := Start(h.app.Endpoint, filepath.Dir(h.s.policy.path), h.person.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, _, err := h.app.Ask(secret, RightAwake); err != nil {
		t.Fatalf("the secret did not survive a restart: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	h := start(t)
	app, tool := h.app, h.tool
	if _, err := app.Register("x", "fly"); err == nil {
		t.Fatal("registered for a right that does not exist")
	}
	if _, err := app.Register("", RightAwake); err == nil {
		t.Fatal("registered without a name")
	}
	if _, err := (&Client{Endpoint: app.Endpoint, Admin: "guess"}).Apps(); err == nil {
		t.Fatal("a guessed admin secret listed the policy")
	}
	if _, err := app.Hold("nonsense", "x"); err == nil {
		t.Fatal("held on a made-up token")
	}

	refused := make(chan error, 1)
	go func() { _, err := app.Register("denied", RightAwake); refused <- err }()
	q := awaitQuestion(t, h.person)
	if _, err := h.person.Answer(q.ID, "never"); err != nil {
		t.Fatal(err)
	}
	if err := <-refused; err == nil {
		t.Fatal("a refused application got a secret")
	}
	if apps, _ := tool.Apps(); len(apps) != 0 {
		t.Fatalf("a refused application was registered: %+v", apps)
	}
	if _, err := app.Register("denied", RightAwake); err == nil {
		t.Fatal("'never' did not hold on the second registration")
	}
	if ps, _ := h.person.Pending(); len(ps) != 0 {
		t.Fatalf("a question answered 'never' was asked again: %+v", ps)
	}
}

func TestGarbageIsClosed(t *testing.T) {
	h := start(t)
	c, err := listen.Dial(h.app.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("{not json\n"))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	if n == 0 {
		t.Fatal("no answer to garbage")
	}
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the connection stayed open after garbage")
	}
}

func TestPlatformAwake(t *testing.T) {
	release, err := keepAwake("rights test", "proving the platform call")
	if err != nil {
		t.Skipf("this machine cannot hold itself awake from here: %v", err)
	}
	release()
}

// Refusal is tested separately from success cases, before any policy state or
// listener can be created. The requested Program proof is never weakened.
func TestProgramProofRefusalPrecedesProvider(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("current macOS socket transport refusal case")
	}
	if err := identity.CanEver(listen.Program); err == nil {
		t.Skip("transport now supplies Program proof; success cases run")
	}
	state := filepath.Join(t.TempDir(), "not-created")
	at := endpoint(t, state, "refused")
	service, err := Start(at, state, "unused")
	if service != nil {
		service.Close()
		t.Fatal("service started without Program proof")
	}
	if !errors.Is(err, identity.ErrNotProven) {
		t.Fatalf("expected proof refusal, got %v", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("provider state created before proof refusal: %v", err)
	}
	if _, err := os.Stat(at); !os.IsNotExist(err) {
		t.Fatalf("listener created before proof refusal: %v", err)
	}
}
