package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

const action = "abstraction.storage/content.read"

var serial atomic.Uint64

func nativeSubject(t *testing.T) wire.Subject {
	t.Helper()
	u, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return wire.Subject{Account: u.Uid, Program: filepath.Clean(exe)}
}
func live(t *testing.T, p *rights.DecisionPolicy, enforcer AuthorizeEnforcer) (*client.Client, string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("Program process/path evidence is not implemented on macOS")
	}
	endpoint := listen.Endpoint(fmt.Sprintf("rights-decision-%d-%d", os.Getpid(), serial.Add(1)))
	h, e := Listen(endpoint, p, enforcer)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background()) }()
	t.Cleanup(func() {
		h.Close()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("rights host failed to drain")
		}
	})
	return client.New(endpoint), endpoint
}
func policy(t *testing.T) (*rights.DecisionPolicy, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, e := rights.LoadDecisionPolicy(path, []string{action})
	if e != nil {
		t.Fatal(e)
	}
	return p, path
}
func TestAuthorizationDirectDoesNotGrantRelay(t *testing.T) {
	p, path := policy(t)
	s := nativeSubject(t)
	if e := p.Set(s, action, "content", true); e != nil {
		t.Fatal(e)
	}
	c, _ := live(t, p, nil)
	r, e := c.DecideContext(context.Background(), action, "content")
	if e != nil || r.Outcome != "permitted" {
		t.Fatal(r, e)
	}
	r, e = c.DecideForContext(context.Background(), s, action, "content")
	if e != nil || r.Outcome != "forbidden" {
		t.Fatal(r, e)
	}
	if e = os.WriteFile(path, []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e = c.DecideForContext(context.Background(), s, action, "content")
	if e != nil || r.Outcome != "forbidden" {
		t.Fatal("relay authorization must precede storage", r, e)
	}
	r, e = c.DecideContext(context.Background(), action, "content")
	if e != nil || r.Outcome != "unavailable" {
		t.Fatal(r, e)
	}
}
func TestAuthorizationTrustedEnforcerAndFreshRevocation(t *testing.T) {
	p, _ := policy(t)
	s := nativeSubject(t)
	if e := p.Set(s, action, "content", true); e != nil {
		t.Fatal(e)
	}
	captured := make(chan *identity.Peer, 8)
	c, _ := live(t, p, func(_ context.Context, peer *identity.Peer, a, r string) bool {
		captured <- peer
		actual, e := client.SubjectFromPeer(peer)
		return e == nil && actual == s && a == action && r == "content"
	})
	r, e := c.DecideForContext(context.Background(), s, action, "content")
	if e != nil || r.Outcome != "permitted" {
		t.Fatal(r, e)
	}
	peer := <-captured
	if e = c.Require(context.Background(), peer, action, "content"); e != nil {
		t.Fatal(e)
	}
	<-captured
	partial := *peer
	partial.Process = identity.Attr[identity.Process]{}
	if _, e = client.SubjectFromPeer(&partial); e == nil {
		t.Fatal("missing Process proof accepted")
	}
	revision := r.PolicyRevision
	if e = p.Revoke(s, action, "content"); e != nil {
		t.Fatal(e)
	}
	e = c.Require(context.Background(), peer, action, "content")
	if !errors.Is(e, client.ErrNotPermitted) {
		t.Fatal(e)
	}
	<-captured
	var denial *client.DecisionError
	if !errors.As(e, &denial) || denial.Outcome != "not_granted" || denial.PolicyRevision == revision {
		t.Fatal(e)
	}
	r, e = c.DecideForContext(context.Background(), s, "different.action", "content")
	if e != nil || r.Outcome != "forbidden" {
		t.Fatal(r, e)
	}
	<-captured
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.DecideContext(ctx, action, "content"); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestAuthorizationOtherProgramCannotClaimEnforcer(t *testing.T) {
	p, _ := policy(t)
	s := nativeSubject(t)
	if e := p.Set(s, action, "content", true); e != nil {
		t.Fatal(e)
	}
	_, endpoint := live(t, p, func(_ context.Context, peer *identity.Peer, a, r string) bool {
		actual, e := client.SubjectFromPeer(peer)
		return e == nil && actual == s && a == action && r == "content"
	})
	data, e := os.ReadFile(s.Program)
	if e != nil {
		t.Fatal(e)
	}
	copyPath := filepath.Join(t.TempDir(), "untrusted-program.exe")
	if e = os.WriteFile(copyPath, data, 0700); e != nil {
		t.Fatal(e)
	}
	subjectJSON, _ := json.Marshal(s)
	cmd := exec.Command(copyPath, "-test.run=^TestAuthorizationChild$")
	cmd.Env = append(os.Environ(), "OA_RIGHTS_CHILD="+endpoint, "OA_RIGHTS_SUBJECT="+string(subjectJSON))
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("child: %v %s", e, out)
	}
}
func TestAuthorizationChild(t *testing.T) {
	endpoint := os.Getenv("OA_RIGHTS_CHILD")
	if endpoint == "" {
		return
	}
	var s wire.Subject
	if json.Unmarshal([]byte(os.Getenv("OA_RIGHTS_SUBJECT")), &s) != nil {
		os.Exit(3)
	}
	c := client.New(endpoint)
	r, e := c.DecideForContext(context.Background(), s, action, "content")
	if e != nil || r.Outcome != "forbidden" {
		os.Exit(4)
	}
	r, e = c.DecideContext(context.Background(), action, "content")
	if e != nil || r.Outcome != "not_granted" {
		os.Exit(5)
	}
	os.Exit(0)
}
