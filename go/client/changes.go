package client

import (
	"context"
	"errors"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// Change requests (RIGHTS-O17): an operator program other than the Panel
// window requests a typed change, which the person confirms in the service's
// popup. ctx must outlive waitMS.

// RequestChangeContext requests one typed change and waits up to waitMS
// (0..30000) for the person's answer. A lost reply is uncertain: list the
// requests before asking again.
func (c *Operator) RequestChangeContext(ctx context.Context, change wire.PolicyChange, waitMS int64) (wire.ChangeRequestState, error) {
	if err := ctx.Err(); err != nil {
		return wire.ChangeRequestState{}, err
	}
	if waitMS < 0 || waitMS > 30000 || (change.ExpectedRevision != "" && !boundedOperatorString(change.ExpectedRevision, 128)) {
		return wire.ChangeRequestState{}, errors.New("rights: invalid change request")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).RequestChange(change, waitMS)
	if err != nil {
		return wire.ChangeRequestState{}, err
	}
	return result, validChangeState(result)
}

// ObserveChangeRequestContext waits up to waitMS (0..30000) for one request
// this program made to settle.
func (c *Operator) ObserveChangeRequestContext(ctx context.Context, id string, waitMS int64) (wire.ChangeRequestState, error) {
	if err := ctx.Err(); err != nil {
		return wire.ChangeRequestState{}, err
	}
	if waitMS < 0 || waitMS > 30000 || !boundedOperatorString(id, 128) {
		return wire.ChangeRequestState{}, errors.New("rights: invalid change request observation")
	}
	result, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ObserveChangeRequest(id, waitMS)
	if err != nil {
		return wire.ChangeRequestState{}, err
	}
	if err := validChangeState(result); err != nil {
		return wire.ChangeRequestState{}, err
	}
	if result.ID != "" && result.ID != id {
		return wire.ChangeRequestState{}, errors.New("rights: mismatched change request")
	}
	return result, nil
}

// ListChangeRequestsContext lists the requests this program made that the
// service still holds.
func (c *Operator) ListChangeRequestsContext(ctx context.Context) (wire.ChangeRequestPage, error) {
	if err := ctx.Err(); err != nil {
		return wire.ChangeRequestPage{}, err
	}
	page, err := wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ListChangeRequests()
	if err != nil {
		return wire.ChangeRequestPage{}, err
	}
	if page.Outcome != wire.PolicyPageOutcomePage && len(page.Requests) != 0 || len(page.Requests) > 64 {
		return wire.ChangeRequestPage{}, errors.New("rights: malformed change request page")
	}
	for _, request := range page.Requests {
		if err := validChangeState(request); err != nil {
			return wire.ChangeRequestPage{}, err
		}
	}
	return page, nil
}

// validChangeState checks that a held request carries its id and change
// together, and that every state only a held request has carries them.
func validChangeState(s wire.ChangeRequestState) error {
	held := s.ID != ""
	if held && !boundedOperatorString(s.ID, 128) || held != (s.Change != nil) {
		return errors.New("rights: malformed change request")
	}
	switch s.Outcome {
	case wire.ChangeRequestOutcomeApplied, wire.ChangeRequestOutcomePending, wire.ChangeRequestOutcomeRefused, wire.ChangeRequestOutcomeExpired:
		if !held {
			return errors.New("rights: malformed change request")
		}
	case wire.ChangeRequestOutcomeUnknown, wire.ChangeRequestOutcomeForbidden:
		if held {
			return errors.New("rights: malformed change request")
		}
	}
	return nil
}
