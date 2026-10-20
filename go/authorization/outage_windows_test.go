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

// A policy file whose read access its ACL denies answers access denied on every
// open. The decision, the operator's rule read and the policy listing read
// unavailable within the native client's ordinary per-call deadline, and read
// the file again once its ACL is restored.
func TestAReadDeniedPolicyIsUnavailablePromptly(t *testing.T) {
	p, path := policy(t)
	subject := nativeSubject(t)
	if err := p.Set(subject, action, "sha256:outage", true); err != nil {
		t.Fatal(err)
	}
	_, decisions, operator, _ := liveOperator(t, p, func(ctx context.Context, _ *identity.Peer) error { return ctx.Err() })
	// RIGHTS-R3 gives each ordinary native call five seconds. The server's
	// policy read may use that call's budget when retrying denied opens.
	const callBudget = 5 * time.Second
	readableCtx, cancelReadable := context.WithTimeout(context.Background(), callBudget)
	defer cancelReadable()
	if d, err := decisions.DecideContext(readableCtx, action, "sha256:outage"); err != nil || d.Outcome != wire.DecisionOutcomePermitted {
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
	timed := func(name string, call func(context.Context) string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), callBudget)
		defer cancel()
		deadline, _ := ctx.Deadline()
		start := time.Now()
		outcome := call(ctx)
		end := time.Now()
		if elapsed := end.Sub(start); outcome != "unavailable" || end.After(deadline) {
			t.Fatalf("%s on a read-denied policy: %q after %v", name, outcome, elapsed)
		}
	}
	timed("Decide", func(ctx context.Context) string {
		d, err := decisions.DecideContext(ctx, action, "sha256:outage")
		if err != nil {
			return err.Error()
		}
		return d.Outcome.String()
	})
	timed("ReadRule", func(ctx context.Context) string {
		r, err := operator.ReadRuleContext(ctx, subject, action, "sha256:outage")
		if err != nil {
			return err.Error()
		}
		return r.Outcome.String()
	})
	timed("ListPolicy", func(ctx context.Context) string {
		page, err := operator.ListPolicyContext(ctx, "", 8)
		if err != nil {
			return err.Error()
		}
		return page.Outcome.String()
	})
	restore()
	restoredCtx, cancelRestored := context.WithTimeout(context.Background(), callBudget)
	defer cancelRestored()
	if r, err := operator.ReadRuleContext(restoredCtx, subject, action, "sha256:outage"); err != nil || r.Outcome != wire.RuleReadOutcomeFound {
		t.Fatalf("restored policy: %+v %v", r, err)
	}
}
