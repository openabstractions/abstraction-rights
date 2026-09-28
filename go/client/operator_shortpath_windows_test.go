//go:build windows

package client_test

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/authorization"
	"github.com/openabstractions/abstraction-rights/go/client"
	"golang.org/x/sys/windows"
)

func TestOperatorUsesCanonicalSubjectForReturnedRules(t *testing.T) {
	const action = "example/content.read"
	long := filepath.Join(t.TempDir(), "rule program", "subject.exe")
	if err := os.MkdirAll(filepath.Dir(long), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(long, []byte("subject"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(long)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	// TEMP may itself contain DOS aliases on hosted Windows runners.
	// Use Win32 as the independent oracle for the complete canonical path.
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("long path: n=%d err=%v", n, err)
	}
	long = windows.UTF16ToString(buf[:n])
	n, err = windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("short path: n=%d err=%v", n, err)
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, long) {
		t.Skip("filesystem has no distinct DOS 8.3 alias")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	subject := wire.Subject{Account: u.Uid, Program: short}
	policy, err := rights.LoadDecisionPolicy(filepath.Join(t.TempDir(), "policy.json"), []string{action})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listen.Endpoint(fmt.Sprintf("rights-client-shortpath-%d-%d", os.Getpid(), time.Now().UnixNano()))
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
	if err != nil || page.Outcome != wire.PolicyPageOutcomePage {
		t.Fatalf("policy: %+v %v", page, err)
	}
	rule := wire.PolicyRule{Subject: subject, Action: action, Resource: "x", Permit: true}
	set, err := op.SetRuleContext(ctx, page.Revision, rule)
	if err != nil || set.Outcome != wire.PolicyEditOutcomeApplied || set.Current == nil || !strings.EqualFold(set.Current.Subject.Program, long) {
		t.Fatalf("set short alias: %+v %v", set, err)
	}
	read, err := op.ReadRuleContext(ctx, subject, action, "x")
	if err != nil || read.Outcome != wire.RuleReadOutcomeFound || read.Record == nil || !strings.EqualFold(read.Record.Rule.Subject.Program, long) {
		t.Fatalf("read short alias: %+v %v", read, err)
	}
	revoked, err := op.RevokeRuleContext(ctx, set.Revision, subject, action, "x")
	if err != nil || revoked.Outcome != wire.PolicyEditOutcomeApplied {
		t.Fatalf("revoke short alias: %+v %v", revoked, err)
	}
	set, err = op.SetRuleForContext(ctx, revoked.Revision, rule, 0, "")
	if err != nil || set.Outcome != wire.PolicyEditOutcomeApplied || set.Current == nil || !strings.EqualFold(set.Current.Subject.Program, long) {
		t.Fatalf("set-for short alias: %+v %v", set, err)
	}
}
