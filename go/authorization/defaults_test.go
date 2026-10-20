package authorization

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// RIGHTS-O13: ListDefaults and SetDefault cross the operator wire under
// operator authorization; a switch turned off refuses the caller's next
// Decide, and turned on permits it again.
func TestOperatorDefaultsOverTheWire(t *testing.T) {
	subject := nativeSubject(t)
	p, err := rights.LoadDecisionPolicy(filepath.Join(t.TempDir(), "decisions.json"), []string{rights.ActionJobSubmit, rights.ActionQuestionAsk})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ConfigureDefaults(subject.Account, []rights.AccountDefault{
		{Name: rights.DefaultDownload, Action: rights.ActionJobSubmit, Resource: rights.ResourceDownloadJobs},
		{Name: rights.DefaultAsk, Action: rights.ActionQuestionAsk, Resource: rights.ResourceAccount},
	}, nil); err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	authorize := func(context.Context, *identity.Peer) error {
		if refuse.Load() {
			return ErrOperatorForbidden
		}
		return nil
	}
	_, decisions, op, _ := liveOperator(t, p, authorize)
	ctx := context.Background()
	page, err := op.ListDefaultsContext(ctx)
	if err != nil || page.Outcome != wire.PolicyPageOutcomePage || len(page.Defaults) != 2 || page.Defaults[0].Name != rights.DefaultAsk || !page.Defaults[1].On {
		t.Fatal(page, err)
	}
	if d, err := decisions.DecideContext(ctx, rights.ActionJobSubmit, rights.ResourceDownloadJobs); err != nil || d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("default did not permit over the wire", d, err)
	}
	off, err := op.SetDefaultContext(ctx, page.Revision, rights.DefaultDownload, false)
	if err != nil || off.Outcome != wire.PolicyEditOutcomeApplied || off.Current.On || off.Current.SetBy == nil || *off.Current.SetBy != subject {
		t.Fatal(off, err)
	}
	if d, err := decisions.DecideContext(ctx, rights.ActionJobSubmit, rights.ResourceDownloadJobs); err != nil || d.Outcome != wire.DecisionOutcomeNotGranted || d.PolicyRevision != off.Revision {
		t.Fatal("switched-off default", d, err)
	}
	stale, err := op.SetDefaultContext(ctx, page.Revision, rights.DefaultDownload, true)
	if err != nil || stale.Outcome != wire.PolicyEditOutcomeConflict {
		t.Fatal(stale, err)
	}
	refuse.Store(true)
	if forbidden, err := op.SetDefaultContext(ctx, off.Revision, rights.DefaultDownload, true); err != nil || forbidden.Outcome != wire.PolicyEditOutcomeForbidden {
		t.Fatal(forbidden, err)
	}
	if forbidden, err := op.ListDefaultsContext(ctx); err != nil || forbidden.Outcome != wire.PolicyPageOutcomeForbidden {
		t.Fatal(forbidden, err)
	}
	refuse.Store(false)
	on, err := op.SetDefaultContext(ctx, off.Revision, rights.DefaultDownload, true)
	if err != nil || on.Outcome != wire.PolicyEditOutcomeApplied || !on.Current.On {
		t.Fatal(on, err)
	}
	if d, err := decisions.DecideContext(ctx, rights.ActionJobSubmit, rights.ResourceDownloadJobs); err != nil || d.Outcome != wire.DecisionOutcomePermitted {
		t.Fatal("switched-on default", d, err)
	}

	// RIGHTS-O14: ExplainFor crosses the wire under the same authorization;
	// a refusal carries no revision, source or name.
	explained, err := op.ExplainForContext(ctx, subject, rights.ActionJobSubmit, rights.ResourceDownloadJobs)
	if err != nil || explained.Outcome != wire.DecisionOutcomePermitted || explained.Source == nil || *explained.Source != wire.DecisionSourceAccountDefault ||
		explained.DefaultName != rights.DefaultDownload || explained.PolicyRevision != on.Revision {
		t.Fatal(explained, err)
	}
	refuse.Store(true)
	if forbidden, err := op.ExplainForContext(ctx, subject, rights.ActionJobSubmit, rights.ResourceDownloadJobs); err != nil ||
		forbidden.Outcome != wire.DecisionOutcomeForbidden || forbidden.Source != nil || forbidden.PolicyRevision != "" || forbidden.DefaultName != "" {
		t.Fatal(forbidden, err)
	}
}
