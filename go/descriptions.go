package rights

import (
	"context"
	"encoding/json"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"slices"
	"strings"
)

type publishedDescription struct {
	Description wire.ActionDescription `json:"description"`
	By          wire.Subject           `json:"by"`
	At          string                 `json:"at"`
}

func descriptionText(s string, max int) bool {
	return boundedDecisionString(s, max) && strings.TrimSpace(s) == s
}
func validStoredDescription(d wire.ActionDescription) bool {
	return ValidActionName(d.Action) && validStoredSubject(d.FeatureApp) &&
		descriptionText(d.AppLabel, 128) && descriptionText(d.Description, 512) && descriptionText(d.DeclaredRisk, 32)
}

// NormalizeActionDescription validates descriptive declarations. FeatureApp is
// the described feature's app, independent of every authorization target.
func NormalizeActionDescription(d wire.ActionDescription) (wire.ActionDescription, error) {
	var err error
	d.FeatureApp, err = NormalizeDecisionSubject(d.FeatureApp)
	d.AppLabel, d.Description, d.DeclaredRisk = strings.TrimSpace(d.AppLabel), strings.TrimSpace(d.Description), strings.TrimSpace(d.DeclaredRisk)
	if err != nil || !validStoredDescription(d) {
		return wire.ActionDescription{}, errors.New("rights: invalid action description")
	}
	return d, nil
}

func describedAction(f decisionFile, action string) wire.DescribedAction {
	item := wire.DescribedAction{Action: action, Choices: []string{"allow", "block", "remove_rule"}}
	for _, d := range f.Descriptions {
		if d.Description.Action == action {
			description, by := d.Description, d.By
			item.Description, item.PublishedBy, item.PublishedAt = &description, &by, d.At
			break
		}
	}
	return item
}

// DescriptionSnapshot exposes published metadata and catalogue names, with no
// rules. The service supplies receiving admission and continuation boundaries.
func (p *DecisionPolicy) DescriptionSnapshot(ctx context.Context) (string, []wire.DescribedAction, error) {
	f, revision, err := p.readDecisionContext(ctx)
	if err != nil {
		return "", nil, err
	}
	actions := []wire.DescribedAction{}
	for _, action := range p.catalogue(f) {
		actions = append(actions, describedAction(f, action))
	}
	return revision, actions, nil
}

// PublishAction registers/corrects metadata under operator authority. Its state
// replacement preserves all existing rules and completed-answer receipts.
func (p *DecisionPolicy) PublishAction(expected string, description wire.ActionDescription, by wire.Subject, authorize func() error) (wire.DescriptionEdit, error) {
	description, err := NormalizeActionDescription(description)
	if err != nil || !boundedDecisionString(expected, 128) {
		return wire.DescriptionEdit{Outcome: wire.ActionEditOutcomeInvalid}, nil
	}
	by, err = NormalizeDecisionSubject(by)
	if err != nil {
		return wire.DescriptionEdit{Outcome: wire.ActionEditOutcomeInvalid}, nil
	}
	if authorize == nil {
		return wire.DescriptionEdit{Outcome: wire.ActionEditOutcomeUnavailable}, errors.New("rights: operator admission required")
	}
	if err = p.regular(); err != nil {
		return wire.DescriptionEdit{Outcome: wire.ActionEditOutcomeUnavailable}, err
	}
	result := wire.DescriptionEdit{}
	noWrite := errors.New("rights: description edit without write")
	capture := func(f decisionFile) {
		result.Revision = p.revision(f)
		if slices.Contains(p.catalogue(f), description.Action) {
			item := describedAction(f, description.Action)
			result.Current = &item
		}
	}
	err = p.change(func(data []byte) ([]byte, error) {
		result = wire.DescriptionEdit{}
		if err := authorize(); err != nil {
			return nil, err
		}
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if p.revision(f) != expected {
			result.Outcome = wire.ActionEditOutcomeConflict
			capture(f)
			return nil, noWrite
		}
		index := slices.IndexFunc(f.Descriptions, func(d publishedDescription) bool { return d.Description.Action == description.Action })
		if index >= 0 && f.Descriptions[index].Description == description {
			result.Outcome = wire.ActionEditOutcomeApplied
			capture(f)
			return nil, noWrite
		}
		if !slices.Contains(p.catalogue(f), description.Action) {
			if len(p.catalogue(f)) >= MaxDecisionActions {
				result.Outcome = wire.ActionEditOutcomeExhausted
				return nil, noWrite
			}
			addAction(&f, registeredAction{Action: description.Action, By: by, At: stamp(p.now())})
		}
		published := publishedDescription{Description: description, By: by, At: stamp(p.now())}
		if index >= 0 {
			f.Descriptions[index] = published
		} else {
			f.Descriptions = append(f.Descriptions, published)
			slices.SortFunc(f.Descriptions, func(a, b publishedDescription) int {
				return strings.Compare(a.Description.Action, b.Description.Action)
			})
		}
		f.Profile = DecisionProfile
		result.Outcome = wire.ActionEditOutcomeApplied
		capture(f)
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return result, nil
	}
	if err != nil {
		return wire.DescriptionEdit{Outcome: wire.ActionEditOutcomeUnavailable}, err
	}
	return result, nil
}
