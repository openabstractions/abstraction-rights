package rights

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

const decisionAction = "abstraction.storage/content.read"

func subject(t *testing.T) wire.Subject {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return wire.Subject{Account: "test-account", Program: identity.CanonicalProgramPath(filepath.Clean(exe))}
}
func TestDecisionPolicyPersistenceRevocationAndNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, e := LoadDecisionPolicy(path, []string{decisionAction})
	if e != nil {
		t.Fatal(e)
	}
	s := subject(t)
	empty := p.Decide(s, decisionAction, "content")
	if empty.Outcome != wire.DecisionOutcomeNotGranted || empty.PolicyRevision == "" {
		t.Fatal(empty)
	}
	if e = p.Revoke(s, decisionAction, "content"); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("noop created file", e)
	}
	if e = p.Set(s, decisionAction, "content", true); e != nil {
		t.Fatal(e)
	}
	permit := p.Decide(s, decisionAction, "content")
	if _, e := LoadPolicy(path); e == nil {
		t.Fatal("legacy loader accepted decision profile")
	}
	legacy := &Policy{path: path}
	if _, _, e := legacy.Add("name", []string{RightAwake}, Seen{}); e == nil {
		t.Fatal("legacy edit overwrote decision profile")
	}
	if permit.Outcome != wire.DecisionOutcomePermitted || permit.PolicyRevision == empty.PolicyRevision {
		t.Fatal(permit)
	}
	before, _ := os.ReadFile(path)
	if e = p.Set(s, decisionAction, "content", true); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("noop changed state")
	}
	reopened, e := LoadDecisionPolicy(path, []string{decisionAction})
	if e != nil {
		t.Fatal(e)
	}
	if reopened.Decide(s, decisionAction, "content").PolicyRevision != permit.PolicyRevision {
		t.Fatal("restart lost revision")
	}
	if e = p.Revoke(s, decisionAction, "content"); e != nil {
		t.Fatal(e)
	}
	if got := reopened.Decide(s, decisionAction, "content"); got.Outcome != wire.DecisionOutcomeNotGranted || got.PolicyRevision == permit.PolicyRevision {
		t.Fatal(got)
	}
	if e = p.Set(s, decisionAction, "content", false); e != nil {
		t.Fatal(e)
	}
	if p.Decide(s, decisionAction, "content").Outcome != wire.DecisionOutcomeDenied {
		t.Fatal("deny lost")
	}
	if p.Decide(s, "other.action", "content").Outcome != wire.DecisionOutcomeUnknownAction || p.Decide(s, decisionAction, "different").Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("implied grant")
	}
	if _, e = LoadDecisionPolicy(path, []string{"different.catalog"}); e == nil {
		t.Fatal("catalog silently changed")
	}
}

func TestDecisionPolicyResourceSpellingIsExact(t *testing.T) {
	p, err := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t)
	if err := p.Set(s, decisionAction, "host:Ollama", true); err != nil {
		t.Fatal(err)
	}
	if got := p.Decide(s, decisionAction, "host:Ollama").Outcome; got != wire.DecisionOutcomePermitted {
		t.Fatalf("exact resource: %s", got)
	}
	if got := p.Decide(s, decisionAction, "host:ollama").Outcome; got != wire.DecisionOutcomeNotGranted {
		t.Fatalf("case-folded resource: %s", got)
	}
	if err := p.Set(s, decisionAction, "host:ollama", false); err != nil {
		t.Fatal(err)
	}
	if got := p.Decide(s, decisionAction, "host:Ollama").Outcome; got != wire.DecisionOutcomePermitted {
		t.Fatalf("distinct permit: %s", got)
	}
	if got := p.Decide(s, decisionAction, "host:ollama").Outcome; got != wire.DecisionOutcomeDenied {
		t.Fatalf("distinct deny: %s", got)
	}
}
func TestDecisionPolicyCorruptionRefusesAndPreserves(t *testing.T) {
	s := subject(t)
	for _, mode := range []string{"duplicate", "conflicting", "oversized", "unknown-profile", "unicode", "nonregular"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "decisions.json")
			p, e := LoadDecisionPolicy(path, []string{decisionAction})
			if e != nil {
				t.Fatal(e)
			}
			if e = p.Set(s, decisionAction, "content", true); e != nil {
				t.Fatal(e)
			}
			data, _ := os.ReadFile(path)
			switch mode {
			case "duplicate", "conflicting":
				var f decisionFile
				if e = json.Unmarshal(data, &f); e != nil {
					t.Fatal(e)
				}
				r := f.Rules[0]
				if mode == "conflicting" {
					r.Permit = false
				}
				f.Rules = append(f.Rules, r)
				data, _ = json.Marshal(f)
			case "oversized":
				data = bytes.Repeat([]byte{' '}, MaxDecisionBytes+1)
			case "unknown-profile":
				data = bytes.Replace(data, []byte(DecisionProfile), []byte("future-profile"), 1)
			case "unicode":
				data = bytes.Replace(data, []byte("test-account"), []byte(`test-\ud800`), 1)
			case "nonregular":
				os.Remove(path)
				if e = os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if mode != "nonregular" {
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if got := p.Decide(s, decisionAction, "content"); got.Outcome != wire.DecisionOutcomeUnavailable || got.PolicyRevision != "" {
				t.Fatal(got)
			}
			if e = p.Revoke(s, decisionAction, "content"); e == nil {
				t.Fatal("corrupt revoke succeeded")
			}
			if mode != "nonregular" {
				after, _ := os.ReadFile(path)
				if !bytes.Equal(data, after) {
					t.Fatal("corrupt state overwritten")
				}
			}
		})
	}
}
func TestDecisionPolicyCapacityAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, e := LoadDecisionPolicy(path, []string{decisionAction})
	if e != nil {
		t.Fatal(e)
	}
	s := subject(t)
	f := decisionFile{Profile: DecisionProfile}
	for i := 0; i < MaxDecisionRules; i++ {
		f.Rules = append(f.Rules, decisionRule{Subject: s, Action: decisionAction, Resource: strings.Repeat("a", i/100+1) + string(rune(1000+i)), Permit: true, SetBy: s, SetAt: "2026-09-15T00:00:00.000Z"})
	}
	// Provider-owned canonical order; a full file can still revoke existing rules.
	slices.SortFunc(f.Rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	data, _ := json.Marshal(f)
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	if e = p.Set(s, decisionAction, "new", true); e == nil {
		t.Fatal("capacity ignored")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("capacity wrote")
	}
	if e = p.Revoke(s, decisionAction, f.Rules[0].Resource); e != nil {
		t.Fatal(e)
	}
	for _, resource := range []string{"", strings.Repeat("a", 1025), "bad\n", "\xff"} {
		if p.Decide(s, decisionAction, resource).Outcome != wire.DecisionOutcomeInvalid {
			t.Fatal("bad resource accepted")
		}
	}
}

// A packaged caller's subject, msix:<package family>, is stored and decided
// like a path subject, and a malformed family is refused.
func TestDecisionPolicyDecidesAPackageFamilySubject(t *testing.T) {
	p, e := LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), []string{decisionAction})
	if e != nil {
		t.Fatal(e)
	}
	packaged := wire.Subject{Account: "test-account", Program: "msix:Claude_pzs8sxrjxfjjc"}
	if e = p.Set(packaged, decisionAction, "content", true); e != nil {
		t.Fatal(e)
	}
	if d := p.Decide(packaged, decisionAction, "content"); d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal(d)
	}
	if d := p.Decide(subject(t), decisionAction, "content"); d.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatalf("a path subject matched the family rule: %+v", d)
	}
	if e = p.Set(wire.Subject{Account: "test-account", Program: "msix:Claude"}, decisionAction, "content", true); e == nil {
		t.Fatal("a malformed package family was stored")
	}
}
