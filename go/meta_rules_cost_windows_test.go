//go:build windows

package rights

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// RIGHTS-R16, R3: reading a holder's meta-rule among costRules rules, the
// check every class-scoped answer makes, does a decision's work alone
// (decisionWork), which keeps it under a millisecond, as a decision is.
func TestMetaRuleDecisionCostAmongHundredRules(t *testing.T) {
	dir := t.TempDir()
	holder := wire.Subject{Account: "test-account", Program: filepath.Join(dir, "opencode.exe")}
	if err := os.WriteFile(holder.Program, []byte("holder"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rules := []decisionRule{{Subject: holder, Action: MetaAnswerAction, Resource: MetaScopeApps, Permit: true,
		SetBy: holder, SetAt: stamp(now), Expires: stamp(now.Add(MetaRuleLapse))}}
	for i := range costRules {
		program := filepath.Join(dir, "program"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26))+".exe")
		if err := os.WriteFile(program, []byte(program), 0o755); err != nil {
			t.Fatal(err)
		}
		rules = append(rules, decisionRule{Subject: wire.Subject{Account: "test-account", Program: program}, Action: decisionAction,
			Resource: "output:image", Permit: true, SetBy: holder, SetAt: stamp(now), Expires: stamp(now.Add(MetaRuleLapse))})
	}
	slices.SortFunc(rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	data, err := json.Marshal(decisionFile{Profile: DecisionProfile, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadDecisionPolicy(path, []string{decisionAction, MetaAnswerAction})
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Decide(holder, MetaAnswerAction, MetaScopeApps); d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatalf("the holder's meta-rule: %v", d.Outcome)
	}
	countDecisionWork(t, p, holder, MetaAnswerAction, MetaScopeApps).check(t, holder.Program)
}
