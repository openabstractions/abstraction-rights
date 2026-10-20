package authorization

import (
	"context"
	"reflect"
	"strings"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestPublishedOperatorConstraintsRemainServiceValidation(t *testing.T) {
	p, _ := policy(t)
	for _, action := range []string{"fixture/second", "fixture/third"} {
		if err := p.RegisterAction(action); err != nil {
			t.Fatal(err)
		}
	}
	_, _, _, endpoint := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	transport := listen.FrameClient{Endpoint: endpoint}
	op := wire.NewAuthorizationOperatorClient(transport)
	typed := wire.NewSelectorAuthorizationOperatorClient(transport)
	before, err := p.OperatorSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][2]string{{"", ""}, {strings.Repeat("r", 129), "question"}, {"revision", "bad\nid"}, {"bad\x07revision", "question"}, {"revision", strings.Repeat("q", 129)}} {
		got, err := op.ApplyFirstUseAllow(ids[0], ids[1])
		if err != nil || got.Outcome != wire.PolicyEditOutcomeInvalid {
			t.Fatal(got, err)
		}
		for _, call := range []func(string, string) (wire.SelectorEdit, error){typed.ApplyPermissionAllow, typed.UndoPermissionEffect} {
			got, err := call(ids[0], ids[1])
			if err != nil || got.Outcome != wire.PolicyEditOutcomeInvalid {
				t.Fatal(got, err)
			}
		}
	}
	subject := nativeSubject(t)
	rules := []wire.PolicyRule{
		{Subject: subject, Action: action, Resource: "bounded", Permit: false},
		{Subject: subject, Action: "fixture/second", Resource: "bounded", Permit: false},
		{Subject: subject, Action: "fixture/third", Resource: "bounded", Permit: false},
	}
	for _, rules := range [][]wire.PolicyRule{nil, rules} {
		got, err := op.SetRulesFor(before.Revision, rules, 0, "")
		if err != nil || got.Outcome != wire.PolicyEditOutcomeInvalid {
			t.Fatal(got, err)
		}
	}
	after, err := p.OperatorSnapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("invalid legacy request changed policy", err)
	}
	// Syntactically valid boundary IDs reach the existing missing-composition
	// refusal, rather than being rejected by a codec or the input validator.
	for _, ids := range [][2]string{{"r", "q"}, {strings.Repeat("é", 64), strings.Repeat("é", 64)}} {
		got, err := op.ApplyFirstUseAllow(ids[0], ids[1])
		if err != nil || got.Outcome != wire.PolicyEditOutcomeUnavailable {
			t.Fatal("valid boundary first-use IDs", got, err)
		}
		for _, call := range []func(string, string) (wire.SelectorEdit, error){typed.ApplyPermissionAllow, typed.UndoPermissionEffect} {
			got, err := call(ids[0], ids[1])
			if err != nil || got.Outcome != wire.PolicyEditOutcomeUnavailable {
				t.Fatal("valid boundary typed IDs", got, err)
			}
		}
	}
	after, err = p.OperatorSnapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("unavailable composition changed policy", err)
	}
	revision := before.Revision
	for _, count := range []int{1, 2} {
		got, err := op.SetRulesFor(revision, rules[:count], 0, "")
		if err != nil || got.Outcome != wire.PolicyEditOutcomeApplied {
			t.Fatal("valid one/two-rule batch", count, got, err)
		}
		revision = got.Revision
	}
}
