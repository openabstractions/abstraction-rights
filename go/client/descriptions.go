package client

import (
	"context"
	"encoding/json"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type ActionDescription = wire.ActionDescription
type DescribedAction = wire.DescribedAction
type DescriptionPage = wire.DescriptionPage
type DescriptionEdit = wire.DescriptionEdit

func validDescription(d ActionDescription) bool {
	return boundedOperatorString(d.Action, 128) && validSubject(d.FeatureApp) &&
		boundedOperatorString(d.AppLabel, 128) && strings.TrimSpace(d.AppLabel) == d.AppLabel &&
		boundedOperatorString(d.Description, 512) && strings.TrimSpace(d.Description) == d.Description &&
		boundedOperatorString(d.DeclaredRisk, 32) && strings.TrimSpace(d.DeclaredRisk) == d.DeclaredRisk
}
func validDescribedAction(a DescribedAction) bool {
	if !boundedOperatorString(a.Action, 128) || !slices.Equal(a.Choices, []string{"allow", "block", "remove_rule"}) {
		return false
	}
	if a.Description == nil {
		return a.PublishedBy == nil && a.PublishedAt == ""
	}
	if !validDescription(*a.Description) || a.Description.Action != a.Action || a.PublishedBy == nil || !validSubject(*a.PublishedBy) {
		return false
	}
	at, err := time.Parse("2006-01-02T15:04:05.000Z", a.PublishedAt)
	return err == nil && at.Format("2006-01-02T15:04:05.000Z") == a.PublishedAt
}

func (c *Client) ListActionDescriptionsContext(ctx context.Context, cursor string, limit int64) (DescriptionPage, error) {
	if err := ctx.Err(); err != nil {
		return DescriptionPage{}, err
	}
	if len(cursor) > 256 || !utf8.ValidString(cursor) || limit < 1 || limit > 64 {
		return DescriptionPage{}, errors.New("rights: invalid description range")
	}
	p, err := wire.NewAuthorizationClient(c.transport.WithContext(ctx)).ListActionDescriptions(cursor, limit)
	if err != nil {
		return DescriptionPage{}, err
	}
	return checkedDescriptionPage(p, cursor, limit)
}

func checkedDescriptionPage(p DescriptionPage, cursor string, limit int64) (DescriptionPage, error) {
	if p.Outcome != wire.PolicyPageOutcomePage {
		if p.Revision != "" || len(p.Actions) != 0 || p.Next != "" || p.Complete {
			return DescriptionPage{}, errors.New("rights: malformed description refusal")
		}
		return p, nil
	}
	if !boundedOperatorString(p.Revision, 128) || int64(len(p.Actions)) > limit || len(p.Next) > 256 || p.Complete != (p.Next == "") || (!p.Complete && (len(p.Actions) == 0 || p.Next == cursor)) {
		return DescriptionPage{}, errors.New("rights: malformed description page")
	}
	for i, a := range p.Actions {
		if !validDescribedAction(a) || (i > 0 && p.Actions[i-1].Action >= a.Action) {
			return DescriptionPage{}, errors.New("rights: malformed action description")
		}
	}
	data, err := json.Marshal(p)
	if err != nil || len(data)+2048+1024*len(p.Actions) > 256<<10 {
		return DescriptionPage{}, errors.New("rights: oversized description page")
	}
	return p, nil
}

func (c *Operator) RegisterDescribedActionContext(ctx context.Context, expected string, d ActionDescription) (DescriptionEdit, error) {
	if err := ctx.Err(); err != nil {
		return DescriptionEdit{}, err
	}
	d.FeatureApp = normalizeOperatorSubject(d.FeatureApp)
	d.AppLabel, d.Description, d.DeclaredRisk = strings.TrimSpace(d.AppLabel), strings.TrimSpace(d.Description), strings.TrimSpace(d.DeclaredRisk)
	if !boundedOperatorString(expected, 128) || !validDescription(d) {
		return DescriptionEdit{}, errors.New("rights: invalid description edit")
	}
	r, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RegisterDescribedAction(expected, d)
	if err != nil {
		return DescriptionEdit{}, err
	}
	return checkedDescriptionEdit(r, d)
}

func checkedDescriptionEdit(r DescriptionEdit, d ActionDescription) (DescriptionEdit, error) {
	switch r.Outcome {
	case wire.ActionEditOutcomeApplied, wire.ActionEditOutcomeConflict:
		if !boundedOperatorString(r.Revision, 128) || (r.Current != nil && (!validDescribedAction(*r.Current) || r.Current.Action != d.Action)) || (r.Outcome == wire.ActionEditOutcomeApplied && (r.Current == nil || r.Current.Description == nil || *r.Current.Description != d)) {
			return DescriptionEdit{}, errors.New("rights: malformed description edit")
		}
	case wire.ActionEditOutcomeInvalid, wire.ActionEditOutcomeExhausted, wire.ActionEditOutcomeForbidden, wire.ActionEditOutcomeUnavailable:
		if r.Revision != "" || r.Current != nil {
			return DescriptionEdit{}, errors.New("rights: malformed description refusal")
		}
	default:
		return DescriptionEdit{}, errors.New("rights: unexpected description edit outcome")
	}
	return r, nil
}
