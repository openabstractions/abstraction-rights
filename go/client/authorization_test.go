package client

import (
	"errors"
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
