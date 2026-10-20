package rights

import (
	"context"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestMetaRefreshBudgetSeparatesPreparationFromPolicyRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		p := &DecisionPolicy{RefreshMetaHolder: func(ctx context.Context) error {
			calls++
			select {
			case <-time.After(600 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		prepared, err := p.PrepareMetaHolderContext(context.Background())
		if err != nil {
			t.Fatal("cooperative multi-owner refresh inherited policy-read budget", err)
		}
		if _, err = p.prepareMetaOperation(prepared, MetaAnswerAction, MetaScopeApps); err != nil || calls != 1 {
			t.Fatal("nested admission did not reuse completed refresh", err, calls)
		}
		if DecisionReadBudget != 500*time.Millisecond {
			t.Fatal("policy-state read budget changed")
		}
	})
}

func TestMetaRefreshBudgetCancellationAndExhaustion(t *testing.T) {
	for _, parentBudget := range []time.Duration{100 * time.Millisecond, 10 * time.Second} {
		t.Run(parentBudget.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithTimeout(context.Background(), parentBudget)
				defer cancel()
				p := &DecisionPolicy{RefreshMetaHolder: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
				start := time.Now()
				_, err := p.PrepareMetaHolderContext(parent)
				expected := parentBudget
				if expected > 5*time.Second {
					expected = 5 * time.Second
				}
				if !errors.Is(err, ErrMetaHolderUnavailable) || time.Since(start) != expected {
					t.Fatal("refresh deadline", err, time.Since(start), expected)
				}
			})
		})
	}
}

func TestMetaRefreshExhaustionPreventsHolderEffect(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	before, err := os.ReadFile(f.p.path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	synctest.Test(t, func(t *testing.T) {
		f.p.RefreshMetaHolder = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		out, err := f.p.ChangeRulesUnderAnswerContext(context.Background(), f.holder, f.appA, []string{decisionAction}, "content", "budget check", "question", func() error { calls++; return nil })
		if !errors.Is(err, ErrMetaHolderUnavailable) || out.Outcome != wire.PolicyEditOutcomeUnavailable || out.Revision != "" || calls != 0 {
			t.Fatal("expired refresh reached effect or disclosed revision", out, err, calls)
		}
	})
	after, err := os.ReadFile(f.p.path)
	if err != nil || string(before) != string(after) {
		t.Fatal("expired refresh changed policy", err)
	}
}
