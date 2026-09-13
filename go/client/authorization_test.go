package client

import (
	"errors"
	"testing"
)

func TestDecisionRequiresConsistentTypedOutcome(t *testing.T) {
	for _, v := range []Decision{{Outcome: "permitted"}, {Outcome: "unavailable", PolicyRevision: "x"}, {Outcome: "future", PolicyRevision: "x"}} {
		if _, e := checked(v, nil); e == nil {
			t.Fatal("accepted", v)
		}
	}
	for _, outcome := range []string{"permitted", "denied", "not_granted", "unknown_action"} {
		if _, e := checked(Decision{Outcome: outcome, PolicyRevision: "revision"}, nil); e != nil {
			t.Fatal(e)
		}
	}
	sentinel := errors.New("transport")
	if _, e := checked(Decision{Outcome: "permitted", PolicyRevision: "x"}, sentinel); e != sentinel {
		t.Fatal("transport error lost")
	}
	if _, e := SubjectFromPeer(nil); e == nil {
		t.Fatal("no evidence accepted")
	}
}
