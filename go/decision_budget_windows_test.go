package rights

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// A blocked policy read that a caller waits for runs to the caller's
// deadline, not to the 500 ms bound a caller without a deadline gets.
func TestPolicyReadFollowsTheCallersDeadline(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	path, err := syscall.UTF16PtrFromString(f.p.path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(path, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	const wait = 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	release := time.AfterFunc(wait/2, func() { syscall.CloseHandle(handle) })
	defer release.Stop()
	start := time.Now()
	if err := f.p.CheckState(ctx); err != nil {
		t.Fatalf("read released after %s inside a %s caller deadline: %v (after %s)", wait/2, wait, err, time.Since(start))
	}
	if took := time.Since(start); took < DecisionReadBudget {
		t.Fatalf("read finished in %s, before the file was released", took)
	}

	blocked, err := syscall.CreateFile(path, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(blocked)
	ctx, cancel = context.WithTimeout(context.Background(), wait)
	defer cancel()
	start = time.Now()
	err = f.p.CheckState(ctx)
	if took := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || took < wait-50*time.Millisecond || took > wait+time.Second {
		t.Fatalf("blocked read with a %s caller deadline: %v after %s", wait, err, took)
	}
}

// A policy file whose ACL denies the read answers within DecisionDeniedRetry
// and some slack, inside a five-second caller deadline: the decision is
// unavailable, never permitted. A held file still follows the caller's
// deadline (above).
func TestAnACLDeniedPolicyReadFailsFast(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	if err := f.p.Set(f.appA, decisionAction, "content", true); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", f.p.path, "/deny", "*S-1-1-0:(RD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls deny: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("icacls", f.p.path, "/reset").Run() })
	if file, err := os.Open(f.p.path); err == nil {
		file.Close()
		t.Skip("this account reads the policy despite the deny")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err := f.p.CheckState(ctx)
	took := time.Since(start)
	if !errors.Is(err, os.ErrPermission) || took > DecisionDeniedRetry+time.Second {
		t.Fatalf("ACL-denied read: %v after %s, want access denied within %s", err, took, DecisionDeniedRetry+time.Second)
	}
	start = time.Now()
	d := f.p.DecideContext(ctx, f.appA, decisionAction, "content")
	if took := time.Since(start); d.Outcome.String() != "unavailable" || took > DecisionDeniedRetry+time.Second {
		t.Fatalf("decision on an ACL-denied policy: %v after %s, want unavailable promptly", d.Outcome, took)
	}
}
