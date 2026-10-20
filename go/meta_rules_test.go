package rights

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// metaFixture is a policy on a settable clock with the meta action and one
// target action catalogued, and four existing programs: the person's Panel,
// the enrolled holder and two apps.
type metaFixture struct {
	p                *DecisionPolicy
	now              time.Time
	mu               sync.Mutex
	panel, holder    wire.Subject
	appA, appB, appC wire.Subject
}

func newMetaFixture(t *testing.T) *metaFixture {
	t.Helper()
	dir := t.TempDir()
	program := func(name string) wire.Subject {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o755); err != nil {
			t.Fatal(err)
		}
		return wire.Subject{Account: "test-account", Program: path}
	}
	f := &metaFixture{now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
		panel: program("panel.exe"), holder: program("opencode.exe"),
		appA: program("comfyui.exe"), appB: program("lemonade.exe"), appC: program("other.exe")}
	p, err := LoadDecisionPolicy(filepath.Join(dir, "decisions.json"), []string{MetaAnswerAction, decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	p.Clock = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	f.p = p
	return f
}

func (f *metaFixture) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func (f *metaFixture) revision(t *testing.T) string {
	t.Helper()
	snap, err := f.p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snap.Revision
}

// enroll is the person's yes: the Panel writes the holder's meta-rule.
func (f *metaFixture) enroll(t *testing.T, ttl time.Duration) wire.PolicyEdit {
	t.Helper()
	permit := true
	edit, err := f.p.ChangeRule(f.revision(t), f.holder, MetaAnswerAction, MetaScopeApps,
		RuleEdit{Permit: &permit, By: f.panel, TTL: ttl, Why: "Let opencode.exe answer", Exact: true}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return edit
}

func (f *metaFixture) stop(t *testing.T) wire.PolicyEdit {
	t.Helper()
	edit, err := f.p.StopAnswerer(f.revision(t), f.holder, true, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return edit
}

func (f *metaFixture) answer(target wire.Subject) (wire.PolicyEdit, error) {
	return f.p.ChangeRuleUnder(f.holder, target, decisionAction, "output:image", true, "answered for the person", func() error { return nil })
}

func (f *metaFixture) decide(s wire.Subject) wire.DecisionOutcome {
	return f.p.Decide(s, decisionAction, "output:image").Outcome
}

// RIGHTS-R16: a class-scoped meta permit carries an expiry within its lapse.
func TestAMetaRulePermitMustLapse(t *testing.T) {
	f := newMetaFixture(t)
	for _, ttl := range []time.Duration{0, MetaRuleLapse + time.Millisecond} {
		if edit := f.enroll(t, ttl); edit.Outcome != wire.PolicyEditOutcomeInvalid {
			t.Fatalf("a meta permit with ttl %v: %v", ttl, edit.Outcome)
		}
	}
	if err := f.p.Set(f.holder, MetaAnswerAction, MetaScopeApps, true); !errors.Is(err, ErrMetaRuleExpiry) {
		t.Fatalf("a native meta permit without expiry: %v", err)
	}
	if edit := f.enroll(t, MetaRuleLapse); edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("a meta permit within its lapse: %v", edit.Outcome)
	}
	// A block on answering is no meta-rule in force and needs no expiry.
	deny := false
	if edit, err := f.p.ChangeRule(f.revision(t), f.holder, MetaAnswerAction, MetaScopeApps, RuleEdit{Permit: &deny, By: f.panel}, func() error { return nil }); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("a meta deny: %+v %v", edit, err)
	}
}

// RIGHTS-R16: the service's own program, and a program the host's
// MetaHolder refuses, never hold a meta-rule: Stop would take the person's
// own rules they set.
func TestAnOperatorCannotHoldAMetaRule(t *testing.T) {
	f := newMetaFixture(t)
	f.p.MetaHolder = func(s wire.Subject) error {
		if s.Program == f.panel.Program {
			return errors.New("an operator program")
		}
		return nil
	}
	permit := true
	for _, holder := range []wire.Subject{f.panel, f.p.native} {
		edit, err := f.p.ChangeRule(f.revision(t), holder, MetaAnswerAction, MetaScopeApps,
			RuleEdit{Permit: &permit, By: f.panel, TTL: MetaRuleLapse}, func() error { return nil })
		if err != nil || edit.Outcome != wire.PolicyEditOutcomeInvalid {
			t.Fatalf("enrolling %s: %+v %v", holder.Program, edit, err)
		}
	}
	if edit := f.enroll(t, MetaRuleLapse); edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("enrolling an app: %v", edit.Outcome)
	}
}

// RIGHTS-R16: a holder writes only under a live meta-rule, never a
// meta-permission and never a rule about itself.
func TestAHolderWritesOnlyUnderALiveMetaRule(t *testing.T) {
	f := newMetaFixture(t)
	if edit, err := f.answer(f.appA); !errors.Is(err, ErrNoMetaRule) || edit.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatalf("no meta-rule: %+v %v", edit, err)
	}
	f.enroll(t, MetaRuleLapse)
	if edit, err := f.p.ChangeRuleUnder(f.holder, f.holder, decisionAction, "output:image", true, "", func() error { return nil }); !errors.Is(err, ErrMetaTarget) || edit.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatalf("a rule about itself: %+v %v", edit, err)
	}
	if edit, err := f.p.ChangeRuleUnder(f.holder, f.appA, MetaAnswerAction, MetaScopeApps, true, "", func() error { return nil }); !errors.Is(err, ErrMetaTarget) || edit.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatalf("passing the power on: %+v %v", edit, err)
	}
	if f.decide(f.appA) != wire.DecisionOutcomeNotGranted || f.decide(f.holder) != wire.DecisionOutcomeNotGranted {
		t.Fatal("a refused holder write landed")
	}
	if edit, err := f.answer(f.appA); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("an answer under the meta-rule: %+v %v", edit, err)
	}
	read := f.p.ReadRule(f.appA, decisionAction, "output:image")
	if read.Record == nil || read.Record.SetBy.Program != f.holder.Program {
		t.Fatalf("the permit's provenance %+v", read.Record)
	}
	f.advance(MetaRuleLapse)
	if edit, err := f.answer(f.appB); !errors.Is(err, ErrNoMetaRule) || edit.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatalf("a lapsed meta-rule: %+v %v", edit, err)
	}
}

// RIGHTS-R16: each answer renews the meta-rule, and the permits the holder
// gave move with it, so every one lasts until the meta-rule ends; the
// meta-rule lapses after MetaRuleLapse without an answer and takes them all.
func TestPermitsAHolderGaveLastUntilItsMetaRuleLapses(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	if _, err := f.answer(f.appA); err != nil {
		t.Fatal(err)
	}
	f.advance(10 * 24 * time.Hour)
	if _, err := f.answer(f.appB); err != nil {
		t.Fatal(err)
	}
	meta := f.p.ReadRule(f.holder, MetaAnswerAction, MetaScopeApps)
	a := f.p.ReadRule(f.appA, decisionAction, "output:image")
	b := f.p.ReadRule(f.appB, decisionAction, "output:image")
	if meta.Record == nil || a.Record == nil || b.Record == nil || a.Record.Expires != meta.Record.Expires || b.Record.Expires != meta.Record.Expires {
		t.Fatalf("expiries meta %+v a %+v b %+v", meta.Record, a.Record, b.Record)
	}
	if meta.Record.Expires != stamp(f.now.Add(MetaRuleLapse)) {
		t.Fatalf("the renewed expiry %s", meta.Record.Expires)
	}
	f.advance(MetaRuleLapse - time.Millisecond)
	if f.decide(f.appA) != wire.DecisionOutcomePermitted || f.decide(f.appB) != wire.DecisionOutcomePermitted {
		t.Fatal("a permit ended before its meta-rule")
	}
	f.advance(time.Millisecond)
	if f.decide(f.appA) != wire.DecisionOutcomeNotGranted || f.decide(f.appB) != wire.DecisionOutcomeNotGranted ||
		f.p.Decide(f.holder, MetaAnswerAction, MetaScopeApps).Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("the lapse left a permit or the meta-rule in force")
	}
}

// Opt-in cleanup removes the enrollment and every permit the holder set,
// and keeps the person's own rules and every deny.
func TestStopRemovesEveryPermitTheHolderSet(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	for _, app := range []wire.Subject{f.appA, f.appB} {
		if edit, err := f.answer(app); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
			t.Fatalf("answer for %s: %+v %v", app.Program, edit, err)
		}
	}
	permit, deny := true, false
	if _, err := f.p.ChangeRule(f.revision(t), f.appC, decisionAction, "output:image", RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A deny the holder set stays: narrowing needs no backer.
	if _, err := f.p.ChangeRule(f.revision(t), f.appC, decisionAction, "input:image", RuleEdit{Permit: &deny, By: f.holder}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if edit := f.stop(t); edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("stop %v", edit.Outcome)
	}
	if f.decide(f.appA) != wire.DecisionOutcomeNotGranted || f.decide(f.appB) != wire.DecisionOutcomeNotGranted {
		t.Fatal("a permit the holder gave outlived Stop")
	}
	if f.decide(f.appC) != wire.DecisionOutcomePermitted {
		t.Fatal("Stop removed the person's own permit")
	}
	if f.p.Decide(f.appC, decisionAction, "input:image").Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("Stop removed a deny the holder set")
	}
	if edit, err := f.answer(f.appA); !errors.Is(err, ErrNoMetaRule) || edit.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatalf("an answer after Stop: %+v %v", edit, err)
	}
}

// RIGHTS-R16: a person's rule on the target stays: a deny conflicts, and a
// permit is not replaced by the holder's, which only renews.
func TestTheHolderNeverReplacesThePersonsRule(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	deny, permit := false, true
	if _, err := f.p.ChangeRule(f.revision(t), f.appA, decisionAction, "output:image", RuleEdit{Permit: &deny, By: f.panel}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if edit, err := f.answer(f.appA); err != nil || edit.Outcome != wire.PolicyEditOutcomeConflict || edit.Current == nil || edit.Current.Permit {
		t.Fatalf("over the person's deny: %+v %v", edit, err)
	}
	if f.decide(f.appA) != wire.DecisionOutcomeDenied {
		t.Fatal("the person's deny was replaced")
	}
	if _, err := f.p.ChangeRule(f.revision(t), f.appB, decisionAction, "output:image", RuleEdit{Permit: &permit, By: f.panel}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if edit, err := f.answer(f.appB); err != nil || edit.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("beside the person's permit: %+v %v", edit, err)
	}
	if read := f.p.ReadRule(f.appB, decisionAction, "output:image"); read.Record == nil || read.Record.SetBy.Program != f.panel.Program || read.Record.Expires != "" {
		t.Fatalf("the person's permit became the holder's %+v", read.Record)
	}
	f.stop(t)
	if f.decide(f.appB) != wire.DecisionOutcomePermitted {
		t.Fatal("Stop removed the person's permit")
	}
}

// RIGHTS-R16: the person enrolling again moves the permits the holder gave
// to the new expiry.
func TestEnrollingAgainMovesTheHoldersPermits(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, 24*time.Hour)
	if _, err := f.answer(f.appA); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Hour)
	f.enroll(t, MetaRuleLapse)
	meta := f.p.ReadRule(f.holder, MetaAnswerAction, MetaScopeApps)
	a := f.p.ReadRule(f.appA, decisionAction, "output:image")
	if meta.Record == nil || a.Record == nil || a.Record.Expires != meta.Record.Expires {
		t.Fatalf("meta %+v permit %+v", meta.Record, a.Record)
	}
}

// RIGHTS-R16 meeting point: Stop arriving while the holder answers. Every
// interleaving ends with no permit the holder set and no meta-rule.
func TestStopDuringAnAnswerLeavesNoPermit(t *testing.T) {
	for round := 0; round < 20; round++ {
		f := newMetaFixture(t)
		f.enroll(t, MetaRuleLapse)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); f.answer(f.appA) }()
		go func() {
			defer wg.Done()
			for {
				edit, err := f.p.StopAnswerer(f.revision(t), f.holder, true, func() error { return nil })
				if err != nil {
					t.Error(err)
					return
				}
				if edit.Outcome != wire.PolicyEditOutcomeConflict {
					return
				}
			}
		}()
		wg.Wait()
		if f.decide(f.appA) != wire.DecisionOutcomeNotGranted {
			t.Fatalf("round %d: a permit outlived Stop", round)
		}
	}
}

// RIGHTS-R16 meeting point: two apps' answers race; both land and both
// expire with the meta-rule.
func TestTwoAnswersRaceAndBothFollowTheMetaRule(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, app := range []wire.Subject{f.appA, f.appB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			edit, err := f.answer(app)
			if err == nil && edit.Outcome != wire.PolicyEditOutcomeApplied {
				err = errors.New(edit.Outcome.String())
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	meta := f.p.ReadRule(f.holder, MetaAnswerAction, MetaScopeApps)
	for _, app := range []wire.Subject{f.appA, f.appB} {
		if r := f.p.ReadRule(app, decisionAction, "output:image"); r.Record == nil || r.Record.Expires != meta.Record.Expires {
			t.Fatalf("%s: %+v, meta-rule %+v", app.Program, r.Record, meta.Record)
		}
	}
}
