package client

import (
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"testing"
)

func TestBatchResponseHonorsExpectedRevision(t *testing.T) {
	request := CheckBatchRequest{ExpectedRevision: "expected", Resources: []ConcreteResource{{}}}
	response := BatchDecision{Outcome: BatchCheckOutcomeChecked, Revision: "different", Outcomes: []DecisionOutcome{DecisionOutcomePermitted}}
	// Exercise the owning codec too: a well-formed response is still invalid
	// when its successful revision contradicts the requested snapshot.
	decoded, err := wire.DecodeBatchDecision(wire.EncodeBatchDecision(&response))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checkedBatch(*decoded, nil, request); err == nil {
		t.Fatal("accepted a different checked revision")
	}
	response.Revision = request.ExpectedRevision
	if _, err = checkedBatch(response, nil, request); err != nil {
		t.Fatal(err)
	}
}
