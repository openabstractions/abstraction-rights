//go:build windows

package rights

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"golang.org/x/sys/windows"
)

// shortAlias returns the short DOS 8.3 spelling of an existing path, and
// false when the filesystem gives it no alias distinct from path itself.
func shortAlias(t *testing.T, path string) (string, bool) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || n >= uint32(len(buf)) {
		t.Fatal("short path exceeds buffer")
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, path) {
		return "", false
	}
	return short, true
}

// A rights rule names its subject's program by whatever spelling a client
// typed or a peer connection reported: a short DOS 8.3 alias when either was
// resolved that way. NormalizeDecisionSubject canonicalizes it
// (identity.CanonicalProgramPath), so a rule granted through one spelling of a
// file matches a decide naming the other, in both directions, while a
// different file that merely shares the real file's base name still does not
// (research/packaged-activation/SPACED-PATH-2026-09-22.md,
// CANONICAL-PATHS-2026-09-22.md).
func TestDecisionPolicyMatchesShortAndLongProgramSpellings(t *testing.T) {
	const account = "test-account"
	spaced := filepath.Join(t.TempDir(), "rule program")
	if err := os.Mkdir(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(spaced, "subject.exe")
	if err := os.WriteFile(long, []byte("subject"), 0o755); err != nil {
		t.Fatal(err)
	}
	short, ok := shortAlias(t, long)
	if !ok {
		t.Skip("filesystem has no distinct DOS alias for this file")
	}
	lookalike := filepath.Join(t.TempDir(), "subject.exe")
	if err := os.WriteFile(lookalike, []byte("lookalike"), 0o755); err != nil {
		t.Fatal(err)
	}

	newPolicy := func(t *testing.T) *DecisionPolicy {
		t.Helper()
		p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), []string{decisionAction})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("granted-short-decided-long", func(t *testing.T) {
		p := newPolicy(t)
		if err := p.Set(wire.Subject{Account: account, Program: short}, decisionAction, "content", true); err != nil {
			t.Fatal(err)
		}
		if d := p.Decide(wire.Subject{Account: account, Program: long}, decisionAction, "content"); d.Outcome != wire.DecisionOutcomePermitted {
			t.Fatalf("rule granted for the short alias %q: decide for the long path %q = %v, want permitted", short, long, d.Outcome)
		}
	})

	t.Run("granted-long-decided-short", func(t *testing.T) {
		p := newPolicy(t)
		if err := p.Set(wire.Subject{Account: account, Program: long}, decisionAction, "content", true); err != nil {
			t.Fatal(err)
		}
		if d := p.Decide(wire.Subject{Account: account, Program: short}, decisionAction, "content"); d.Outcome != wire.DecisionOutcomePermitted {
			t.Fatalf("rule granted for the long path %q: decide for the short alias %q = %v, want permitted", long, short, d.Outcome)
		}
		if d := p.Decide(wire.Subject{Account: account, Program: lookalike}, decisionAction, "content"); d.Outcome == wire.DecisionOutcomePermitted {
			t.Fatalf("rule granted for %q: decide for the lookalike file %q = permitted, want not_granted", long, lookalike)
		}
	})
}
