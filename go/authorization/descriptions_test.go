package authorization

import (
	"context"
	"fmt"
	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDescriptionPublicationAdmissionPagingAndStaleRevision(t *testing.T) {
	p, _ := policy(t)
	s := nativeSubject(t)
	var deny atomic.Bool
	_, reader, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error {
		if deny.Load() {
			return ErrOperatorForbidden
		}
		return nil
	})
	ctx := context.Background()
	page, err := reader.ListActionDescriptionsContext(ctx, "", 1)
	if err != nil || page.Outcome != wire.PolicyPageOutcomePage {
		t.Fatal(page, err)
	}
	d := wire.ActionDescription{Action: "opencode/log-source.share", FeatureApp: wire.Subject{Account: "declared-account", Program: s.Program}, AppLabel: "OpenCode", Description: "Share event contents with the assistant model", DeclaredRisk: "routine"}
	added, err := op.RegisterDescribedActionContext(ctx, page.Revision, d)
	if err != nil || added.Outcome != wire.ActionEditOutcomeApplied || *added.Current.PublishedBy != s || added.Current.Description.FeatureApp.Account == s.Account {
		t.Fatal(added, err)
	}
	if decision, err := reader.DecideContext(ctx, d.Action, "windows/application"); err != nil || decision.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("declared routine risk granted permission", decision, err)
	}
	one, err := reader.ListActionDescriptionsContext(ctx, "", 1)
	if err != nil || one.Next == "" {
		t.Fatal(one, err)
	}
	two, err := reader.ListActionDescriptionsContext(ctx, one.Next, 1)
	if err != nil || !two.Complete || len(two.Actions) != 1 || two.Actions[0].Description == nil || *two.Actions[0].PublishedBy != s {
		t.Fatal(two, err)
	}
	parts := strings.Split(one.Next, ":")
	parts[2] = strings.Repeat("0", 64)
	if gap, err := reader.ListActionDescriptionsContext(ctx, strings.Join(parts, ":"), 1); err != nil || gap.Outcome != wire.PolicyPageOutcomeGap {
		t.Fatal("foreign subject cursor admitted", gap, err)
	}
	_, restarted, _, _ := liveOperator(t, p, nil)
	if gap, err := restarted.ListActionDescriptionsContext(ctx, one.Next, 1); err != nil || gap.Outcome != wire.PolicyPageOutcomeGap {
		t.Fatal("cursor survived a new service lifetime", gap, err)
	}
	deny.Store(true)
	d.Description = "Corrected description"
	if refused, err := op.RegisterDescribedActionContext(ctx, added.Revision, d); err != nil || refused.Outcome != wire.ActionEditOutcomeForbidden {
		t.Fatal(refused, err)
	}
	// Reading published descriptions requires native admission, not policy editing authority.
	if read, err := reader.ListActionDescriptionsContext(ctx, "", 64); err != nil || read.Outcome != wire.PolicyPageOutcomePage {
		t.Fatal(read, err)
	}
	deny.Store(false)
	changed, err := op.RegisterDescribedActionContext(ctx, added.Revision, d)
	if err != nil || changed.Outcome != wire.ActionEditOutcomeApplied {
		t.Fatal(changed, err)
	}
	if gap, err := reader.ListActionDescriptionsContext(ctx, one.Next, 1); err != nil || gap.Outcome != wire.PolicyPageOutcomeGap {
		t.Fatal(gap, err)
	}
	if stale, err := op.RegisterDescribedActionContext(ctx, added.Revision, d); err != nil || stale.Outcome != wire.ActionEditOutcomeConflict || stale.Revision != changed.Revision {
		t.Fatal(stale, err)
	}
}

func TestDescriptionPagesBoundEncodedReply(t *testing.T) {
	p, _ := policy(t)
	s := nativeSubject(t)
	_, reader, op, _ := liveOperator(t, p, func(context.Context, *identity.Peer) error { return nil })
	ctx := context.Background()
	page, err := reader.ListActionDescriptionsContext(ctx, "", 64)
	if err != nil {
		t.Fatal(err)
	}
	rev := page.Revision
	// Existing program syntax supports absent administrative paths; the descriptor
	// does not open or prove the declared feature app's executable.
	program := s.Program[:strings.LastIndexAny(s.Program, "/\\")+1] + strings.Repeat("long-folder/", 300) + "app.exe"
	for i := 0; i < 50; i++ {
		d := wire.ActionDescription{Action: fmt.Sprintf("bulk/a%02d", i), FeatureApp: wire.Subject{Account: s.Account, Program: program}, AppLabel: strings.Repeat("l", 128), Description: strings.Repeat("\\", 512), DeclaredRisk: "sensitive"}
		r, err := op.RegisterDescribedActionContext(ctx, rev, d)
		if err != nil || r.Outcome != wire.ActionEditOutcomeApplied {
			t.Fatal(i, r, err)
		}
		rev = r.Revision
	}
	read, err := reader.ListActionDescriptionsContext(ctx, "", 64)
	if err != nil || read.Complete || read.Next == "" || len(read.Actions) == 0 {
		t.Fatal("long descriptions did not cut the page", read, err)
	}
	count := len(read.Actions)
	for !read.Complete {
		read, err = reader.ListActionDescriptionsContext(ctx, read.Next, 64)
		if err != nil || read.Outcome != wire.PolicyPageOutcomePage {
			t.Fatal(read, err)
		}
		count += len(read.Actions)
	}
	if count != 51 {
		t.Fatal("pagination lost/duplicated descriptions", count)
	}
}
