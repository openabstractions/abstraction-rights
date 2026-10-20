package client

import (
	"errors"
	"reflect"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestDecisionRequiresConsistentTypedOutcome(t *testing.T) {
	for _, v := range []Decision{{Outcome: wire.DecisionOutcomePermitted}, {Outcome: wire.DecisionOutcomeUnavailable, PolicyRevision: "x"}, {Outcome: wire.DecisionOutcome(99), PolicyRevision: "x"}} {
		if _, e := checked(v, nil); e == nil {
			t.Fatal("accepted", v)
		}
	}
	for _, outcome := range []wire.DecisionOutcome{wire.DecisionOutcomePermitted, wire.DecisionOutcomeDenied, wire.DecisionOutcomeNotGranted, wire.DecisionOutcomeUnknownAction} {
		if _, e := checked(Decision{Outcome: outcome, PolicyRevision: "revision"}, nil); e != nil {
			t.Fatal(e)
		}
	}
	sentinel := errors.New("transport")
	if _, e := checked(Decision{Outcome: wire.DecisionOutcomePermitted, PolicyRevision: "x"}, sentinel); e != sentinel {
		t.Fatal("transport error lost")
	}
	if _, e := SubjectFromPeer(nil); e == nil {
		t.Fatal("no evidence accepted")
	}
}

func TestRevisionDecisionAliasPreservesCanonicalIdentity(t *testing.T) {
	if reflect.TypeFor[RevisionDecision]() != reflect.TypeFor[wire.RevisionDecision]() {
		t.Fatal("revision decision identity")
	}
}

func TestPermittedOrNotGranted(t *testing.T) {
	for _, outcome := range append(wire.DecisionOutcomeValues(), 0, 99) {
		want := outcome == wire.DecisionOutcomePermitted || outcome == wire.DecisionOutcomeNotGranted
		if PermittedOrNotGranted(outcome) != want {
			t.Errorf("%s: expected eligibility %t", outcome, want)
		}
	}
}

func TestEvaluatedDecisionOutcomeAndPublishedErrorField(t *testing.T) {
	for _, outcome := range wire.DecisionOutcomeValues() {
		evaluated := outcome == wire.DecisionOutcomePermitted || outcome == wire.DecisionOutcomeDenied || outcome == wire.DecisionOutcomeNotGranted || outcome == wire.DecisionOutcomeUnknownAction
		if Evaluated(outcome) != evaluated {
			t.Fatal("evaluated set differs from Decision contract", outcome)
		}
		// A variable string still initializes the published v0.5.0 field.
		word := outcome.String()
		refusal := &DecisionError{Outcome: word, PolicyRevision: "revision"}
		if refusal.DecisionOutcome() != outcome || !errors.Is(refusal, ErrNotPermitted) {
			t.Fatal("typed accessor changed refusal behavior", refusal)
		}
	}
	for _, word := range []string{"", "future", "Denied"} {
		refusal := &DecisionError{Outcome: word}
		if Evaluated(refusal.DecisionOutcome()) {
			t.Fatal("unknown word became evaluated", word)
		}
	}
	var absent *DecisionError
	if Evaluated(absent.DecisionOutcome()) || Evaluated(wire.DecisionOutcome(99)) {
		t.Fatal("absent or unknown decision became evaluated")
	}
}
