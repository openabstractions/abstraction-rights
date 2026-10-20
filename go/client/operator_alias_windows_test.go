//go:build windows

package client_test

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/authorization"
	"github.com/openabstractions/abstraction-rights/go/client"
)

// RIGHTS-R10: a stored alias and a query for the same file are one program.
// The fixture files are inert data; no fixture program is executed.
func TestOperatorAcceptsSameFileAliasRules(t *testing.T) {
	dir := t.TempDir()
	program, alias := filepath.Join(dir, "subject.exe"), filepath.Join(dir, "alias.exe")
	if err := os.WriteFile(program, []byte("subject"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(program, alias); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	const action, second, resource = "example/content.read", "example/content.write", "output:image"
	policy, err := rights.LoadDecisionPolicy(filepath.Join(dir, "policy.json"), []string{action, second})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listen.Endpoint(fmt.Sprintf("rights-client-alias-%d-%d", os.Getpid(), time.Now().UnixNano()))
	host, err := authorization.Listen(endpoint, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.EnableOperator(func(context.Context, *identity.Peer) error { return nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- host.Serve(context.Background()) }()
	t.Cleanup(func() {
		host.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("operator did not drain")
		}
	})
	op := client.NewOperator(endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	page, err := op.ListPolicyContext(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	rule := wire.PolicyRule{Subject: wire.Subject{Account: u.Uid, Program: alias}, Action: action, Resource: resource, Permit: true}
	set, err := op.SetRuleContext(ctx, page.Revision, rule)
	if err != nil || set.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("store alias: %+v %v", set, err)
	}
	target := wire.Subject{Account: u.Uid, Program: program}
	read, err := op.ReadRuleContext(ctx, target, action, resource)
	if err != nil || read.Outcome != wire.RuleReadOutcomeFound || read.Record == nil || read.Record.Rule.Subject.Program != alias {
		t.Fatalf("read same-file alias: %+v %v", read, err)
	}
	rule.Subject = target
	conflict, err := op.SetRuleContext(ctx, page.Revision, rule)
	if err != nil || conflict.Outcome != wire.PolicyEditOutcomeConflict || conflict.Current == nil || conflict.Current.Subject.Program != alias {
		t.Fatalf("edit current alias: %+v %v", conflict, err)
	}
	group := []wire.PolicyRule{rule, {Subject: target, Action: second, Resource: resource, Permit: true}}
	conflict, err = op.SetRulesForContext(ctx, page.Revision, group, 0, "")
	if err != nil || conflict.Outcome != wire.PolicyEditOutcomeConflict || conflict.Current == nil || conflict.Current.Subject.Program != alias {
		t.Fatalf("group current alias: %+v %v", conflict, err)
	}
	group[1].Subject.Program = alias
	set, err = op.SetRulesForContext(ctx, read.Revision, group, 0, "")
	if err != nil || set.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("group same-file aliases: %+v %v", set, err)
	}
	for _, bad := range []wire.Subject{{Account: "another-account", Program: alias}, {Account: u.Uid, Program: filepath.Join(dir, "different.exe")}} {
		group[1].Subject = bad
		if _, err := op.SetRulesForContext(ctx, set.Revision, group, 0, ""); err == nil {
			t.Fatalf("different grouped subject accepted: %+v", bad)
		}
	}
	for _, alter := range []func(*wire.PolicyRule){
		func(r *wire.PolicyRule) { r.Resource = "other" },
		func(r *wire.PolicyRule) { r.Action = action },
		func(r *wire.PolicyRule) { r.Permit = false },
	} {
		bad := []wire.PolicyRule{rule, {Subject: target, Action: second, Resource: resource, Permit: true}}
		alter(&bad[1])
		if _, err := op.SetRulesForContext(ctx, set.Revision, bad, 0, ""); err == nil {
			t.Fatalf("invalid group accepted: %+v", bad)
		}
	}
	if revoked, err := op.RevokeRuleContext(ctx, set.Revision, target, action, resource); err != nil || revoked.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("revoke alias: %+v %v", revoked, err)
	}
}
