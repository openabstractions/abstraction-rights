package rights

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func TestDecisionReadFailureLogsOneStageAndPreservesRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	p, err := LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	s := subject(t)
	if err = p.Set(s, decisionAction, "content", true); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("invalid owned decision state"), 0600); err != nil {
		t.Fatal(err)
	}
	before := p.Decide(s, decisionAction, "content")
	var records bytes.Buffer
	p.Logger = slog.New(slog.NewJSONHandler(&records, nil))
	after := p.Decide(s, decisionAction, "content")
	if after.Outcome != wire.DecisionOutcomeUnavailable || after.PolicyRevision != "" || after != before {
		t.Fatalf("refusal changed: before=%+v after=%+v", before, after)
	}
	lines := bytes.Split(bytes.TrimSpace(records.Bytes()), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("got %d records: %s", len(lines), records.Bytes())
	}
	var record map[string]any
	if err = json.Unmarshal(lines[0], &record); err != nil {
		t.Fatal(err)
	}
	if record["level"] != "WARN" || record["msg"] != "rights decision unavailable" || record["stage"] != "read" || record["error"] == "" || record["error"] == nil {
		t.Fatalf("missing failure stage: %s", lines[0])
	}
	if len(record) != 5 {
		t.Fatalf("unexpected disclosure fields: %s", lines[0])
	}
}
