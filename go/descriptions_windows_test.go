//go:build windows

package rights

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLegacyCompletedAnswerSurvivesLoadSubjectCanonicalization(t *testing.T) {
	long, short, recreate := laterProgram(t)
	path := filepath.Join(t.TempDir(), "policy.json")
	f := decisionFile{Profile: completedAnswerDecisionProfile, Rules: []decisionRule{storedRule(t, short, "content", false, time.Now())}, AppliedOperatorAnswers: []string{strings.Repeat("c", 32)}}
	data, _ := json.Marshal(f)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	recreate()
	if got, ok := shortAlias(t, long); !ok || got != short {
		t.Skip("recreated file has a different short alias")
	}
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	loaded, _, err := p.readDecision()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profile != DecisionProfile || loaded.Rules[0].Subject.Program != long || loaded.Rules[0].Permit || !reflect.DeepEqual(loaded.AppliedOperatorAnswers, f.AppliedOperatorAnswers) || len(loaded.Descriptions) != 0 {
		t.Fatal(loaded)
	}
}
