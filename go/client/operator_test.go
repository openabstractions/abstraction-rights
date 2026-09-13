package client

import (
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"testing"
)

func TestOperatorRefusesForgedEditResults(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s := Subject{Account: "account", Program: exe}
	permit := true
	rule := PolicyRule{Subject: s, Action: "action", Resource: "resource", Permit: true}
	badRule := rule
	badRule.Resource = "other"
	for _, v := range []wire.PolicyEdit{
		{Outcome: "applied", Revision: "revision"},
		{Outcome: "conflict", Current: &rule},
		{Outcome: "forbidden", Revision: "revision"},
		{Outcome: "applied", Revision: "revision", Current: &badRule},
	} {
		if _, err := checkedPolicyEdit(v, nil, s, "action", "resource", &permit); err == nil {
			t.Fatal("forged edit accepted", v)
		}
	}
	if _, err := checkedPolicyEdit(wire.PolicyEdit{Outcome: "applied", Revision: "revision", Current: &rule}, nil, s, "action", "resource", nil); err == nil {
		t.Fatal("revoke accepted retained rule")
	}
}
