package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPublishedDescriptionPreservesRulesReceiptsAndAuthority(t *testing.T) {
	p, path, now := clocked(t, decisionAction)
	s := subject(t)
	by := wire.Subject{Account: "operator", Program: s.Program}
	d := wire.ActionDescription{Action: "opencode/log-source.share", FeatureApp: wire.Subject{Account: "described-app", Program: s.Program}, AppLabel: "OpenCode", Description: "Share log event contents with the assistant model; it may be hosted", DeclaredRisk: "sensitive"}
	allow := func() error { return nil }
	revision, _, err := p.DescriptionSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	added, err := p.PublishAction(revision, d, by, allow)
	if err != nil || added.Outcome != wire.ActionEditOutcomeApplied || added.Current == nil || *added.Current.PublishedBy != by || added.Current.Description.FeatureApp != d.FeatureApp {
		t.Fatal(added, err)
	}
	if v := p.Decide(s, d.Action, "windows/application"); v.Outcome != wire.DecisionOutcomeNotGranted {
		t.Fatal("publication granted", v)
	}
	if err := p.Set(s, d.Action, "windows/application", true); err != nil {
		t.Fatal(err)
	}
	if err := p.Set(s, d.Action, "other", false); err != nil {
		t.Fatal(err)
	}
	beforeData, _ := os.ReadFile(path)
	before, err := p.decodeDecision(beforeData)
	if err != nil {
		t.Fatal(err)
	}
	before.Profile = completedAnswerDecisionProfile
	before.Descriptions = nil
	before.AppliedOperatorAnswers = []string{strings.Repeat("a", 32)}
	before.Rules[0].Expires = stamp(now.Add(time.Hour))
	legacy, _ := json.Marshal(before)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	p, err = LoadDecisionPolicy(path, []string{decisionAction})
	if err != nil {
		t.Fatal(err)
	}
	p.Clock = func() time.Time { return *now }
	if data, _ := os.ReadFile(path); !bytes.Equal(data, legacy) {
		t.Fatal("canonical legacy load eagerly migrated")
	}
	revision, _, _ = p.DescriptionSnapshot(context.Background())
	first, err := p.PublishAction(revision, d, by, allow)
	if err != nil || first.Outcome != wire.ActionEditOutcomeApplied {
		t.Fatal(first, err)
	}
	afterData, _ := os.ReadFile(path)
	after, err := p.decodeDecision(afterData)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Rules, after.Rules) || !reflect.DeepEqual(before.Actions, after.Actions) || !reflect.DeepEqual(before.AppliedOperatorAnswers, after.AppliedOperatorAnswers) {
		t.Fatal("first metadata publication changed rules/provenance/receipts")
	}
	if again, err := p.PublishAction(first.Revision, d, by, allow); err != nil || again.Revision != first.Revision {
		t.Fatal(again, err)
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(data, afterData) {
		t.Fatal("identical description wrote")
	}
	*now = now.Add(time.Minute)
	d.Description = "Share the named log source's event contents with the assistant model; it may be hosted"
	newBy := wire.Subject{Account: "another-operator", Program: s.Program}
	changed, err := p.PublishAction(first.Revision, d, newBy, allow)
	if err != nil || changed.Outcome != wire.ActionEditOutcomeApplied || changed.Revision == first.Revision || *changed.Current.PublishedBy != newBy || changed.Current.PublishedAt == first.Current.PublishedAt {
		t.Fatal(changed, err)
	}
	data, _ := os.ReadFile(path)
	current, err := p.decodeDecision(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.Rules, current.Rules) || !reflect.DeepEqual(after.AppliedOperatorAnswers, current.AppliedOperatorAnswers) {
		t.Fatal("metadata correction changed permissions/receipts")
	}
	if conflict, err := p.PublishAction(first.Revision, d, by, allow); err != nil || conflict.Outcome != wire.ActionEditOutcomeConflict || conflict.Revision != changed.Revision {
		t.Fatal(conflict, err)
	}
	if refused, err := p.PublishAction(changed.Revision, d, by, func() error { return errors.New("revoked operator") }); err == nil || refused.Outcome != wire.ActionEditOutcomeUnavailable {
		t.Fatal(refused, err)
	}
	if dataAfter, _ := os.ReadFile(path); !bytes.Equal(dataAfter, data) {
		t.Fatal("refused edit wrote")
	}
	retired, err := p.EditAction(changed.Revision, d.Action, false, by, allow)
	if err != nil || retired.Outcome != wire.ActionEditOutcomeApplied {
		t.Fatal(retired, err)
	}
	f, _, err := p.readDecision()
	if err != nil || len(f.Descriptions) != 0 || len(f.Rules) != 0 || !reflect.DeepEqual(f.AppliedOperatorAnswers, before.AppliedOperatorAnswers) {
		t.Fatal("retirement damaged retained receipt or kept metadata", f, err)
	}
}

func TestDescriptionValidationAndLegacyProfiles(t *testing.T) {
	p, path, _ := clocked(t, decisionAction)
	s := subject(t)
	d := wire.ActionDescription{Action: decisionAction, FeatureApp: s, AppLabel: "app", Description: "description", DeclaredRisk: "future-word"}
	for _, profile := range []string{previousDecisionProfile, answerIdentityDecisionProfile, completedAnswerDecisionProfile} {
		f := decisionFile{Profile: profile}
		if profile == completedAnswerDecisionProfile {
			f.AppliedOperatorAnswers = []string{strings.Repeat("b", 32)}
		}
		data, _ := json.Marshal(f)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadDecisionPolicy(path, []string{decisionAction})
		if err != nil {
			t.Fatal(profile, err)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
			t.Fatal("legacy load changed", profile)
		}
		rev, items, err := loaded.DescriptionSnapshot(context.Background())
		if err != nil || len(items) != 1 || items[0].Description != nil {
			t.Fatal(items, err)
		}
		out, err := loaded.PublishAction(rev, d, s, func() error { return nil })
		if err != nil || out.Outcome != wire.ActionEditOutcomeApplied {
			t.Fatal(profile, out, err)
		}
		current, _, err := loaded.readDecision()
		if err != nil || current.Profile != DecisionProfile || !reflect.DeepEqual(current.AppliedOperatorAnswers, f.AppliedOperatorAnswers) {
			t.Fatal(current, err)
		}
		current.Profile = completedAnswerDecisionProfile
		bad, _ := json.Marshal(current)
		if _, err := p.decodeDecision(bad); err == nil {
			t.Fatal("descriptions accepted under older profile")
		}
	}
	for _, mutate := range []func(*wire.ActionDescription){func(d *wire.ActionDescription) { d.Action = "INVALID/action" }, func(d *wire.ActionDescription) { d.Description = " \t " }, func(d *wire.ActionDescription) { d.AppLabel = strings.Repeat("x", 129) }, func(d *wire.ActionDescription) { d.FeatureApp.Program = "relative" }} {
		bad := d
		mutate(&bad)
		if _, err := NormalizeActionDescription(bad); err == nil {
			t.Fatal("invalid descriptor accepted", bad)
		}
	}
}
