package client

import (
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorEditsMatchProgramIdentity(t *testing.T) {
	dir := t.TempDir()
	program, alias, different := filepath.Join(dir, "subject.exe"), filepath.Join(dir, "alias.exe"), filepath.Join(dir, "different.exe")
	for _, path := range []string{program, different} {
		if err := os.WriteFile(path, []byte("inert fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(program, alias); err != nil {
		t.Fatal(err)
	}
	s := Subject{Account: "account", Program: program}
	permit := true
	rule := PolicyRule{Subject: Subject{Account: s.Account, Program: alias}, Action: "example/content.read", Resource: "output:image", Permit: true}
	valid := wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: "revision", Current: &rule}
	if _, err := checkedPolicyEdit(valid, nil, s, rule.Action, rule.Resource, &permit); err != nil {
		t.Fatalf("same-file current rule refused: %v", err)
	}
	for _, bad := range []PolicyRule{
		{Subject: Subject{Account: "other", Program: alias}, Action: rule.Action, Resource: rule.Resource, Permit: true},
		{Subject: Subject{Account: s.Account, Program: different}, Action: rule.Action, Resource: rule.Resource, Permit: true},
		{Subject: rule.Subject, Action: "example/content.write", Resource: rule.Resource, Permit: true},
		{Subject: rule.Subject, Action: rule.Action, Resource: "other", Permit: true},
		{Subject: rule.Subject, Action: rule.Action, Resource: rule.Resource, Permit: false},
	} {
		result := valid
		result.Current = &bad
		if _, err := checkedPolicyEdit(result, nil, s, rule.Action, rule.Resource, &permit); err == nil {
			t.Fatalf("different current rule accepted: %+v", bad)
		}
	}
}

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
		{Outcome: wire.PolicyEditOutcomeApplied, Revision: "revision"},
		{Outcome: wire.PolicyEditOutcomeConflict, Current: &rule},
		{Outcome: wire.PolicyEditOutcomeForbidden, Revision: "revision"},
		{Outcome: wire.PolicyEditOutcomeApplied, Revision: "revision", Current: &badRule},
	} {
		if _, err := checkedPolicyEdit(v, nil, s, "action", "resource", &permit); err == nil {
			t.Fatal("forged edit accepted", v)
		}
	}
	if _, err := checkedPolicyEdit(wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeApplied, Revision: "revision", Current: &rule}, nil, s, "action", "resource", nil); err == nil {
		t.Fatal("revoke accepted retained rule")
	}
}
