package authorization

import (
	"context"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
	watch "github.com/openabstractions/abstraction-watch/go"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitPolicyObservers(t *testing.T, h *Host, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.observationGate.Waiting() != want {
		if time.Now().After(deadline) {
			t.Fatalf("waiters=%d want=%d", h.observationGate.Waiting(), want)
		}
		runtime.Gosched()
	}
}

func TestPolicyObserveNativeChangeGapAndPresenterClose(t *testing.T) {
	p, _ := policy(t)
	h, _, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	ctx := context.Background()
	first, err := op.ObservePolicyContext(ctx, "", 0)
	if err != nil || first.Outcome != wire.PolicyObservationOutcomeChanged || first.Next == "" || first.Revision == "" || first.Mechanism != wire.PolicyObservationMechanismNative {
		t.Fatal(first, err)
	}
	quiet, err := op.ObservePolicyContext(ctx, first.Next, 0)
	if err != nil || quiet.Outcome != wire.PolicyObservationOutcomeUnchanged || quiet.Next != first.Next || quiet.Revision != first.Revision {
		t.Fatal(quiet, err)
	}
	f := watch.Follow(ctx, first.Next, func(ctx context.Context, after string) func(func(client.PolicyObservation, error) bool) {
		return op.ObservePolicyPagesContext(ctx, after, 30000)
	}, func(page client.PolicyObservation) (string, bool) {
		return page.Next, page.Outcome == wire.PolicyObservationOutcomeGap
	})
	waitPolicyObservers(t, h, 1)
	edit, err := op.SetRuleContext(ctx, first.Revision, wire.PolicyRule{Subject: nativeSubject(t), Action: action, Resource: "observed", Permit: true})
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		f.Close()
		t.Fatal(edit, err)
	}
	changed, err := f.Next(ctx)
	if err != nil || changed.Revision != edit.Revision || changed.Next == first.Next {
		f.Close()
		t.Fatal(changed, err)
	}
	waitPolicyObservers(t, h, 1)
	f.Close()
	waitPolicyObservers(t, h, 0)
	if _, err := f.Next(ctx); !errors.Is(err, watch.ErrClosed) {
		t.Fatal(err)
	}
	foreign := strings.Repeat("0", 32) + first.Next[32:]
	gap, err := op.ObservePolicyContext(ctx, foreign, 0)
	if err != nil || gap.Outcome != wire.PolicyObservationOutcomeGap || gap.Next != foreign || gap.Revision != "" {
		t.Fatal(gap, err)
	}
	// Follow must turn the real generated gap into a fresh service snapshot.
	f = watch.Follow(ctx, foreign, func(ctx context.Context, after string) func(func(client.PolicyObservation, error) bool) {
		return op.ObservePolicyPagesContext(ctx, after, 0)
	}, func(page client.PolicyObservation) (string, bool) {
		return page.Next, page.Outcome == wire.PolicyObservationOutcomeGap
	})
	fresh, err := f.Next(ctx)
	f.Close()
	if err != nil || fresh.Outcome != wire.PolicyObservationOutcomeChanged || fresh.Revision != edit.Revision || fresh.Next == foreign {
		t.Fatal(fresh, err)
	}
}

func TestPolicyObserveRechecksAuthorityAndSourceAfterWake(t *testing.T) {
	for _, reason := range []string{"denied", "outage", "source"} {
		t.Run(reason, func(t *testing.T) {
			p, path := policy(t)
			if reason == "source" {
				if err := p.Set(nativeSubject(t), action, "source", true); err != nil {
					t.Fatal(err)
				}
				p.StateRequired = true
			}
			var changed atomic.Bool
			h, _, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error {
				if changed.Load() && reason == "denied" {
					return ErrOperatorForbidden
				}
				if changed.Load() && reason == "outage" {
					return errors.New("operator outage")
				}
				return nil
			})
			initial, err := op.ObservePolicyContext(context.Background(), "", 0)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan client.PolicyObservation, 1)
			go func() {
				page, e := op.ObservePolicyContext(context.Background(), initial.Next, 2000)
				if e != nil {
					t.Error(e)
				}
				done <- page
			}()
			waitPolicyObservers(t, h, 1)
			changed.Store(true)
			if reason == "source" {
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			h.observationGate.Advance()
			select {
			case page := <-done:
				want := wire.PolicyObservationOutcomeUnavailable
				if reason == "denied" {
					want = wire.PolicyObservationOutcomeForbidden
				}
				if page.Outcome != want || page.Next != "" || page.Revision != "" {
					t.Fatal(page)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("wake did not settle")
			}
		})
	}
}

func TestPolicyObserveCapacityCancellationAndBounds(t *testing.T) {
	p, _ := policy(t)
	h, _, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	initial, err := op.ObservePolicyContext(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { _, e := op.ObservePolicyContext(ctx, initial.Next, 30000); done <- e }()
	}
	waitPolicyObservers(t, h, 16)
	full, err := op.ObservePolicyContext(context.Background(), initial.Next, 0)
	if err != nil || full.Outcome != wire.PolicyObservationOutcomeUnchanged {
		t.Fatal("zero wait needs no slot", full, err)
	}
	full, err = op.ObservePolicyContext(context.Background(), initial.Next, 1)
	if err != nil || full.Outcome != wire.PolicyObservationOutcomeUnavailable {
		t.Fatal(full, err)
	}
	cancel()
	for i := 0; i < 16; i++ {
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cancel did not drain")
		}
	}
	waitPolicyObservers(t, h, 0)
	for _, after := range []string{"wrong", strings.Repeat("x", 257)} {
		page, e := op.ObservePolicyContext(context.Background(), after, 0)
		if len(after) > 256 {
			if e == nil {
				t.Fatal("oversize admitted")
			}
		} else if e != nil || page.Outcome != wire.PolicyObservationOutcomeInvalid {
			t.Fatal(page, e)
		}
	}
}

func TestPolicyObserveCursorBindsReceivingProgramAndHostEpoch(t *testing.T) {
	p, _ := policy(t)
	_, _, op, endpoint := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	first, err := op.ObservePolicyContext(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "observation-program.exe")
	if err = os.WriteFile(copied, data, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(copied, "-test.run=^TestOperatorCallerProcess$")
	cmd.Env = append(os.Environ(), "OA_RIGHTS_OPERATOR="+endpoint, "OA_RIGHTS_OBSERVE_AFTER="+first.Next, "OA_RIGHTS_WANT=gap")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("foreign Program: %v %s", e, out)
	}
	_, _, restarted, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	gap, err := restarted.ObservePolicyContext(context.Background(), first.Next, 0)
	if err != nil || gap.Outcome != wire.PolicyObservationOutcomeGap || gap.Revision != "" {
		t.Fatal(gap, err)
	}
}

func TestPolicyObserveExpiryWakeRechecksAuthority(t *testing.T) {
	p, _ := policy(t)
	var denied atomic.Bool
	h, _, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error {
		if denied.Load() {
			return ErrOperatorForbidden
		}
		return nil
	})
	page, err := op.ListPolicyContext(context.Background(), "", 1)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := op.SetRuleForContext(context.Background(), page.Revision, wire.PolicyRule{Subject: nativeSubject(t), Action: action, Resource: "expires", Permit: true}, 300*time.Millisecond, "")
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	initial, err := op.ObservePolicyContext(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan client.PolicyObservation, 1)
	go func() {
		answer, e := op.ObservePolicyContext(context.Background(), initial.Next, 2000)
		if e != nil {
			t.Error(e)
		}
		done <- answer
	}()
	waitPolicyObservers(t, h, 1)
	denied.Store(true) // No Advance: expiry itself must wake and recheck.
	select {
	case answer := <-done:
		if answer.Outcome != wire.PolicyObservationOutcomeForbidden || answer.Revision != "" || answer.Next != "" {
			t.Fatal(answer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expiry did not wake")
	}
}

func TestPolicyObserveFixedServiceClockKeepsAbsoluteWaitBound(t *testing.T) {
	p, _ := policy(t)
	fixed := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	p.Clock = func() time.Time { return fixed }
	var reads atomic.Int32
	_, _, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error { reads.Add(1); return nil })
	page, err := op.ListPolicyContext(context.Background(), "", 1)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := op.SetRuleForContext(context.Background(), page.Revision, wire.PolicyRule{Subject: nativeSubject(t), Action: action, Resource: "clock", Permit: true}, 10*time.Millisecond, "")
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	initial, err := op.ObservePolicyContext(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	reads.Store(0)
	start := time.Now()
	answer, err := op.ObservePolicyContext(context.Background(), initial.Next, 50)
	if err != nil || answer.Outcome != wire.PolicyObservationOutcomeUnchanged || time.Since(start) < 50*time.Millisecond || time.Since(start) > time.Second {
		t.Fatal(answer, err, time.Since(start))
	}
	if reads.Load() > 20 {
		t.Fatal("foreign clock deadline spun", reads.Load())
	}
}

func TestPolicyObserveExpiryCrossesBlockedRecheck(t *testing.T) {
	p, _ := policy(t)
	var active atomic.Bool
	var checks atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	_, _, op, _ := liveOperator(t, p, func(ctx context.Context, _ *identity.Peer) error {
		if active.Load() && checks.Add(1) == 2 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	page, err := op.ListPolicyContext(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := op.SetRuleForContext(ctx, page.Revision, wire.PolicyRule{Subject: nativeSubject(t), Action: action, Resource: "crossed", Permit: true}, time.Second, "")
	if err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatal(edit, err)
	}
	rule, err := op.ReadRuleContext(ctx, nativeSubject(t), action, "crossed")
	if err != nil || rule.Record == nil {
		t.Fatal(rule, err)
	}
	expiry, err := time.Parse(rights.StampFormat, rule.Record.Expires)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := op.ObservePolicyContext(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(true)
	done := make(chan client.PolicyObservation, 1)
	go func() {
		answer, e := op.ObservePolicyContext(ctx, initial.Next, 2000)
		if e != nil && ctx.Err() == nil {
			t.Error(e)
		}
		done <- answer
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("recheck did not enter")
	}
	if !time.Now().Before(expiry) {
		t.Fatal("fixture did not enter recheck before expiry")
	}
	timer := time.NewTimer(time.Until(expiry))
	<-timer.C
	close(release)
	select {
	case answer := <-done:
		if answer.Outcome != wire.PolicyObservationOutcomeChanged || answer.Next == initial.Next || answer.Revision != edit.Revision {
			t.Fatal(answer)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("expiry was delayed to full observation wait")
	}
}
