package authorization

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// promptOutage is how soon a decision point answers unavailable for a policy
// file whose read is denied: the policy's read budget plus transport slack.
const promptOutage = 1500 * time.Millisecond

// A policy file whose read access its ACL denies answers access denied on every
// open. The decision, the operator's rule read and the policy listing read
// unavailable within the policy's read budget, and read the file again once its
// ACL is restored.
func TestAReadDeniedPolicyIsUnavailablePromptly(t *testing.T) {
	p, path := policy(t)
	subject := nativeSubject(t)
	if err := p.Set(subject, action, "sha256:outage", true); err != nil {
		t.Fatal(err)
	}
	_, decisions, operator, _ := liveOperator(t, p, func(ctx context.Context, _ *identity.Peer) error { return ctx.Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if d, err := decisions.DecideContext(ctx, action, "sha256:outage"); err != nil || d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatalf("readable policy: %+v %v", d, err)
	}
	if out, err := exec.Command("icacls", path, "/deny", "*S-1-1-0:(RD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls deny: %v\n%s", err, out)
	}
	restore := func() { exec.Command("icacls", path, "/reset").Run() }
	t.Cleanup(restore)
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Skip("this account reads the policy despite the deny")
	}
	timed := func(name string, call func() string) {
		t.Helper()
		start := time.Now()
		outcome := call()
		if elapsed := time.Since(start); outcome != "unavailable" || elapsed > promptOutage {
			t.Fatalf("%s on a read-denied policy: %q after %v", name, outcome, elapsed)
		}
	}
	timed("Decide", func() string {
		d, err := decisions.DecideContext(ctx, action, "sha256:outage")
		if err != nil {
			return err.Error()
		}
		return d.Outcome.String()
	})
	timed("ReadRule", func() string {
		r, err := operator.ReadRuleContext(ctx, subject, action, "sha256:outage")
		if err != nil {
			return err.Error()
		}
		return r.Outcome.String()
	})
	timed("ListPolicy", func() string {
		page, err := operator.ListPolicyContext(ctx, "", 8)
		if err != nil {
			return err.Error()
		}
		return page.Outcome.String()
	})
	restore()
	if r, err := operator.ReadRuleContext(ctx, subject, action, "sha256:outage"); err != nil || r.Outcome != wire.RuleReadOutcomeFound {
		t.Fatalf("restored policy: %+v %v", r, err)
	}
}
