//go:build windows

package rights

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// costRules is the size of the policy the decision cost is measured on.
const costRules = 100

// costPolicy writes a state of costRules permits on one action and
// resource, each for its own existing program, plus extra, and returns the
// loaded policy and a caller whose existing program matches none of them, so
// a decision compares every rule.
func costPolicy(tb testing.TB, extra ...decisionRule) (*DecisionPolicy, wire.Subject) {
	tb.Helper()
	dir := tb.TempDir()
	caller := wire.Subject{Account: "test-account", Program: filepath.Join(dir, "caller.exe")}
	if err := os.WriteFile(caller.Program, []byte("caller"), 0o755); err != nil {
		tb.Fatal(err)
	}
	at := stamp(time.Now())
	rules := slices.Clone(extra)
	for i := range costRules {
		program := filepath.Join(dir, "program"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26))+".exe")
		if err := os.WriteFile(program, []byte(program), 0o755); err != nil {
			tb.Fatal(err)
		}
		rules = append(rules, decisionRule{Subject: wire.Subject{Account: "test-account", Program: program}, Action: decisionAction,
			Resource: "content", Permit: true, SetBy: caller, SetAt: at})
	}
	slices.SortFunc(rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	data, err := json.Marshal(decisionFile{Profile: DecisionProfile, Rules: rules})
	if err != nil {
		tb.Fatal(err)
	}
	path := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		tb.Fatal(err)
	}
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		tb.Fatal(err)
	}
	return p, caller
}

// BenchmarkDecideAmongHundredRules is one decision whose caller is compared
// with costRules stored programs that all exist.
func BenchmarkDecideAmongHundredRules(b *testing.B) {
	p, caller := costPolicy(b)
	if d := p.Decide(caller, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
		b.Fatalf("the caller matched a rule: %v", d.Outcome)
	}
	b.ResetTimer()
	for b.Loop() {
		p.Decide(caller, decisionAction, "content")
	}
}

// costDecisions is how many decisions the cost tests count work over.
const costDecisions = 200

// decisionWork is the filesystem and decoding work costDecisions decisions of
// caller on action and resource did, counted rather than timed, so a loaded
// machine changes nothing: how often each program's file identity was opened
// or read by name, and whether the decoded state was decoded again. span runs
// from the warm decision's decode to the last decision; it bounds how often
// StoredKeyReuse let a stored identity or the state be read again.
type decisionWork struct {
	opens    map[string]int
	redecode bool
	span     time.Duration
}

func countDecisionWork(t *testing.T, p *DecisionPolicy, caller wire.Subject, action, resource string) decisionWork {
	t.Helper()
	p.Decide(caller, action, resource)
	p.decoded.mu.Lock()
	decodedAt := p.decoded.read
	p.decoded.mu.Unlock()
	var mu sync.Mutex
	work := decisionWork{opens: map[string]int{}}
	stop, ok := identity.ObserveOpens(func(path string) {
		mu.Lock()
		work.opens[strings.ToLower(filepath.Clean(path))]++
		mu.Unlock()
	})
	if !ok {
		t.Fatal("another test holds identity's open observer")
	}
	for range costDecisions {
		p.Decide(caller, action, resource)
	}
	work.span = time.Since(decodedAt)
	stop()
	p.decoded.mu.Lock()
	work.redecode = !p.decoded.read.Equal(decodedAt)
	p.decoded.mu.Unlock()
	return work
}

// check fails t unless the decisions did only the work that keeps one under a
// millisecond on this machine (BenchmarkDecideAmongHundredRules, 0.38 ms;
// 21.9 ms before R3, when every decision opened every stored program): the
// caller's identity read at most once per decision, each stored program's at
// most once per StoredKeyReuse, and the state decoded again only past it.
func (w decisionWork) check(t *testing.T, caller string) {
	t.Helper()
	windows := 1 + int(w.span/StoredKeyReuse)
	callerOpens := 0
	for path, n := range w.opens {
		if strings.EqualFold(path, filepath.Clean(caller)) {
			callerOpens += n
			continue
		}
		if n > windows {
			t.Errorf("stored program %s was read %d times in %v; StoredKeyReuse allows %d", path, n, w.span, windows)
		}
	}
	if callerOpens > costDecisions {
		t.Errorf("the caller's identity was read %d times in %d decisions", callerOpens, costDecisions)
	}
	if w.redecode && w.span < StoredKeyReuse {
		t.Errorf("the unchanged state was decoded again within %v", w.span)
	}
	t.Logf("%d decisions in %v: %d caller reads, %d paths read", costDecisions, w.span, callerOpens, len(w.opens))
}

// R3: a decision among costRules rules on its own action and resource stays
// under a millisecond: names are compared first, the caller's file identity
// is read once, stored programs' identities are reused within a revision, and
// unchanged state is not decoded again. The test counts that work; the
// benchmark above measures the time, which on a loaded machine measures the
// load.
func TestDecisionCostAmongHundredRules(t *testing.T) {
	p, caller := costPolicy(t)
	if d := p.Decide(caller, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("the caller matched a rule: %v", d.Outcome)
	}
	countDecisionWork(t, p, caller, decisionAction, "content").check(t, caller.Program)
}

// R3: a stored rule for a program on a share never slows a decision: no
// decision opens it, as identity's open observer records, so a caller
// elsewhere is decided at once, and a caller spelling the share program by
// another case is denied by name.
func TestAStoredShareRuleNeverSlowsADecision(t *testing.T) {
	share := `\\192.0.2.1\share\Tools\app.exe`
	deny := decisionRule{Subject: wire.Subject{Account: "test-account", Program: share}, Action: decisionAction,
		Resource: "content", Permit: false, SetBy: wire.Subject{Account: "test-account", Program: share}, SetAt: stamp(time.Now())}
	p, caller := costPolicy(t, deny)
	var mu sync.Mutex
	var shareOpens []string
	stop, ok := identity.ObserveOpens(func(path string) {
		if strings.HasPrefix(path, `\\`) || strings.Contains(path, "192.0.2.1") {
			mu.Lock()
			shareOpens = append(shareOpens, path)
			mu.Unlock()
		}
	})
	if !ok {
		t.Fatal("another test holds identity's open observer")
	}
	defer stop()
	if d := p.Decide(caller, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("a local caller: %v", d.Outcome)
	}
	if d := p.Decide(wire.Subject{Account: "test-account", Program: `\\192.0.2.1\SHARE\tools\APP.EXE`}, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("the share program by another case: %v, want denied", d.Outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(shareOpens) != 0 {
		t.Fatalf("decisions beside a share rule opened %q", shareOpens)
	}
}

// R3 follow-up: names that match only ignoring case are not one program
// when both exist: a deny for App.exe in a case-sensitive folder does not
// decide app.exe beside it, and still decides App.exe.
func TestADenyInACaseSensitiveFolderKeepsToItsOwnFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "case-sensitive")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("fsutil.exe", "file", "setCaseSensitiveInfo", dir, "enable").CombinedOutput(); err != nil {
		t.Skipf("fsutil cannot make a case-sensitive folder here: %v %s", err, out)
	}
	upper, lower := filepath.Join(dir, "App.exe"), filepath.Join(dir, "app.exe")
	for _, program := range []string{upper, lower} {
		if err := os.WriteFile(program, []byte(program), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	deny := decisionRule{Subject: wire.Subject{Account: "test-account", Program: upper}, Action: decisionAction,
		Resource: "content", Permit: false, SetBy: wire.Subject{Account: "test-account", Program: upper}, SetAt: stamp(time.Now())}
	p, _ := costPolicy(t, deny)
	if d := p.Decide(wire.Subject{Account: "test-account", Program: lower}, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("%q beside a deny for %q: %v, want not_granted", lower, upper, d.Outcome)
	}
	if d := p.Decide(wire.Subject{Account: "test-account", Program: upper}, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("%q with its own deny: %v, want denied", upper, d.Outcome)
	}
}

// R3: a stored program's file identity is reused within a revision for at
// most StoredKeyReuse. A deny for a program not yet installed decides a
// caller reaching it through a junction once that reuse ends, and at once
// after any edit changes the revision.
func TestAStoredProgramInstalledLaterIsSeenByFileIdentity(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "later")
	program := filepath.Join(folder, "app.exe")
	junction := filepath.Join(dir, "alias")
	deny := decisionRule{Subject: wire.Subject{Account: "test-account", Program: program}, Action: decisionAction,
		Resource: "content", Permit: false, SetBy: wire.Subject{Account: "test-account", Program: program}, SetAt: stamp(time.Now())}
	p, _ := costPolicy(t, deny)
	viaJunction := wire.Subject{Account: "test-account", Program: filepath.Join(junction, "app.exe")}
	if d := p.Decide(viaJunction, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("before the install: %v", d.Outcome)
	}
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, folder).CombinedOutput(); err != nil {
		t.Skipf("this volume will not hold a junction: %v %s", err, out)
	}
	// The absent reading is still within its reuse: age it past the bound.
	p.stored.mu.Lock()
	if k, ok := p.stored.keys[program]; !ok || k.key != "" {
		p.stored.mu.Unlock()
		t.Fatalf("the absent program's reading: %+v %v", k, ok)
	} else {
		k.read = k.read.Add(-StoredKeyReuse)
		p.stored.keys[program] = k
	}
	p.stored.mu.Unlock()
	if d := p.Decide(viaJunction, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("after the install, through a junction: %v, want denied", d.Outcome)
	}
	// A fresh policy revision reads it again at once.
	q, _ := costPolicy(t, deny)
	if d := q.Decide(viaJunction, decisionAction, "content"); d.Outcome != wire.DecisionOutcomeDenied {
		t.Fatalf("a new revision through a junction: %v, want denied", d.Outcome)
	}
}
