package rights

import (
	"context"
	"path/filepath"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func explain(t *testing.T, p *DecisionPolicy, s wire.Subject, action, resource string) wire.DecisionExplanation {
	t.Helper()
	return p.ExplainForContext(context.Background(), s, action, resource)
}

func wantExplained(t *testing.T, got wire.DecisionExplanation, outcome wire.DecisionOutcome, source wire.DecisionSource, name string) {
	t.Helper()
	if got.Outcome != outcome || got.Source == nil || *got.Source != source || got.DefaultName != name || got.PolicyRevision == "" {
		s := "<nil>"
		if got.Source != nil {
			s = got.Source.String()
		}
		t.Fatalf("explained %s/%s/%q, want %s/%s/%q", got.Outcome, s, got.DefaultName, outcome, source, name)
	}
}

// RIGHTS-O14: the explanation is the decision's own evaluation with the step
// that decided it: a default by name, the program's own rule over it, a
// default the program is excluded from, and none. It records nothing.
func TestExplainForNamesTheDecidingStep(t *testing.T) {
	script := scriptHost(t)
	p := defaultsPolicy(t, filepath.Join(t.TempDir(), "decisions.json"), script)
	s := subject(t)
	before := selectorRevision(t, p)
	got := explain(t, p, s, ActionJobSubmit, ResourceDownloadJobs)
	wantExplained(t, got, wire.DecisionOutcomePermitted, wire.DecisionSourceAccountDefault, DefaultDownload)
	if d := p.Decide(s, ActionJobSubmit, ResourceDownloadJobs); d.Outcome != got.Outcome || d.PolicyRevision != got.PolicyRevision {
		t.Fatalf("the explanation %+v differs from the decision %+v", got, d)
	}
	wantExplained(t, explain(t, p, s, ActionApplicationAnnounce, "app:alpha"), wire.DecisionOutcomePermitted, wire.DecisionSourceAccountDefault, DefaultAnnounce)
	wantExplained(t, explain(t, p, script, ActionJobSubmit, ResourceDownloadJobs), wire.DecisionOutcomeNotGranted, wire.DecisionSourceDefaultExcluded, DefaultDownload)
	wantExplained(t, explain(t, p, s, ActionJobSubmit, "other-jobs"), wire.DecisionOutcomeNotGranted, wire.DecisionSourceNone, "")
	if after := selectorRevision(t, p); after != before {
		t.Fatalf("explaining changed the revision %s -> %s", before, after)
	}
	if err := p.Set(s, ActionJobSubmit, ResourceDownloadJobs, false); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, s, ActionJobSubmit, ResourceDownloadJobs), wire.DecisionOutcomeDenied, wire.DecisionSourceOwnRule, "")
	if err := p.Set(s, ActionJobSubmit, ResourceDownloadJobs, true); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, s, ActionJobSubmit, ResourceDownloadJobs), wire.DecisionOutcomePermitted, wire.DecisionSourceOwnRule, "")
	if got := explain(t, p, wire.Subject{Account: s.Account, Program: "relative.exe"}, ActionJobSubmit, ResourceDownloadJobs); got.Outcome != wire.DecisionOutcomeInvalid || got.Source != nil || got.PolicyRevision != "" {
		t.Fatalf("an invalid subject explained %+v", got)
	}
}

// RIGHTS-O14: a live typed Block decides before the program's own exact
// permit, and the explanation says so.
func TestExplainForNamesATypedBlock(t *testing.T) {
	p, s := testSelectorPolicy(t)
	setTestSelector(t, p, s, testSelection(selectorUse, "alpha"), false)
	if err := p.Set(s, selectorUse, "name:alpha", true); err != nil {
		t.Fatal(err)
	}
	wantExplained(t, explain(t, p, s, selectorUse, "name:alpha"), wire.DecisionOutcomeDenied, wire.DecisionSourceTypedBlock, "")
	wantExplained(t, explain(t, p, s, selectorUse, "name:beta"), wire.DecisionOutcomeNotGranted, wire.DecisionSourceNone, "")
}
