package client

import (
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"testing"
)

func TestDescriptionRepliesKeepMetadataSeparateFromPermission(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := ActionDescription{Action: "opencode/log-source.share", FeatureApp: Subject{Account: "feature account", Program: exe}, AppLabel: "OpenCode", Description: "Share event contents", DeclaredRisk: "sensitive"}
	by := Subject{Account: "operator account", Program: exe}
	a := DescribedAction{Action: d.Action, Choices: []string{"allow", "block", "remove_rule"}, Description: &d, PublishedBy: &by, PublishedAt: "2026-10-05T12:00:00.000Z"}
	p := DescriptionPage{Outcome: wire.PolicyPageOutcomePage, Revision: "revision", Actions: []DescribedAction{a}, Complete: true}
	if _, err := checkedDescriptionPage(p, "", 64); err != nil {
		t.Fatal(err)
	}
	e := DescriptionEdit{Outcome: wire.ActionEditOutcomeApplied, Revision: "revision", Current: &a}
	if _, err := checkedDescriptionEdit(e, d); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DescriptionPage){
		func(p *DescriptionPage) { p.Actions[0].PublishedBy = nil },
		func(p *DescriptionPage) { p.Actions[0].Choices = []string{"allow"} },
		func(p *DescriptionPage) { p.Actions[0].Action = "other/action" },
		func(p *DescriptionPage) { p.Actions = append(p.Actions, p.Actions[0]) },
		func(p *DescriptionPage) { p.Complete = false },
		func(p *DescriptionPage) { p.Outcome = wire.PolicyPageOutcomeForbidden },
	} {
		bad := p
		bad.Actions = append([]DescribedAction(nil), p.Actions...)
		change(&bad)
		if _, err := checkedDescriptionPage(bad, "", 64); err == nil {
			t.Fatalf("forged page accepted: %+v", bad)
		}
	}
	for _, bad := range []DescriptionEdit{
		{Outcome: wire.ActionEditOutcomeApplied, Revision: "revision"},
		{Outcome: wire.ActionEditOutcomeConflict, Current: &a},
		{Outcome: wire.ActionEditOutcomeForbidden, Revision: "revision"},
		{Outcome: wire.ActionEditOutcomeUnknown, Revision: "revision"},
	} {
		if _, err := checkedDescriptionEdit(bad, d); err == nil {
			t.Fatalf("forged edit accepted: %+v", bad)
		}
	}
}
