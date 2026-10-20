package rights

import (
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// RIGHTS-R23: every committed change reaches every OnChange function before
// the edit returns, a grant and a revoke alike, so each owner that keeps
// something alive under a rule can end what a revoked rule kept (the
// resource service's leases, RES-L7; inference's running operations,
// INF-A6). A refused edit commits nothing and calls nothing; a removed
// function is called no more while the others still are.
func TestEveryCommittedChangeCallsOnChange(t *testing.T) {
	dir := t.TempDir()
	policy, err := LoadDecisionPolicy(filepath.Join(dir, "decisions.json"), []string{AwakeAction})
	if err != nil {
		t.Fatal(err)
	}
	calls, others := 0, 0
	remove := policy.OnChange(func() { calls++ })
	policy.OnChange(func() { others++ })
	policy.OnChange(nil)
	app := wire.Subject{Account: "S-1-5-21-7-1001", Program: filepath.Join(dir, "app.exe")}
	if err := policy.Set(app, AwakeAction, AwakeResource, true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || others != 1 {
		t.Fatalf("a grant called OnChange %d and %d times", calls, others)
	}
	if err := policy.Revoke(app, AwakeAction, AwakeResource); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || others != 2 {
		t.Fatalf("a revoke called OnChange %d and %d times in all", calls, others)
	}
	if err := policy.Set(app, "abstraction.unknown/thing", AwakeResource, true); err == nil {
		t.Fatal("an uncatalogued action was written")
	}
	if calls != 2 || others != 2 {
		t.Fatalf("a refused edit called OnChange: %d and %d calls", calls, others)
	}
	remove()
	if err := policy.Set(app, AwakeAction, AwakeResource, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("a removed OnChange was called: %d calls", calls)
	}
	if others != 3 {
		t.Fatalf("removing one OnChange stopped another: %d calls", others)
	}
}
