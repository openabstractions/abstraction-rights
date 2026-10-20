package client

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteSubjectAdministrativeTargetAndNativeActorStayDistinct(t *testing.T) {
	s := Subject{Account: "receiver", Program: "remote:" + strings.Repeat("a", 64)}
	r := PolicyRule{Subject: s, Action: "abstraction.router/route", Resource: "abstraction.router/routes", Permit: true}
	if !validPolicyRule(r) || validSubject(s) || normalizeOperatorSubject(s) != s {
		t.Fatal("target/actor distinction")
	}
	if !samePolicyProgram(s.Program, s.Program) || samePolicyProgram(s.Program, "remote:"+strings.Repeat("b", 64)) ||
		samePolicyProgram(s.Program, filepath.Join(t.TempDir(), "runtime.exe")) {
		t.Fatal("remote/native comparison")
	}
	r.Subject.Program = "remote:*"
	if validPolicyRule(r) {
		t.Fatal("wildcard target accepted")
	}
}
