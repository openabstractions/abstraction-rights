package authorization

import (
	"context"
	"errors"
	"time"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// Rights changes through operator programs (RIGHTS-O17, architect ruling A of
// 2026-11-22). The Panel window's edits stay direct. Every other operator
// program's change is a typed request the person confirms in a person-only
// popup, unless the caller's own connection-bound token is elevated and the
// elevated-callers default is on. The runtime owns the request, the question
// and the Activity line; this host routes the calls.

// OperatorChanges is trusted runtime composition. Every method must honor ctx
// and be safe for concurrent calls. by is the operator subject the host
// established from the receiving peer.
type OperatorChanges interface {
	// Admit decides how this operator peer's edits apply: nil for the Panel
	// window's direct edits, ErrChangeExempt for an elevated caller whose
	// change the service applies and records itself (Apply), and
	// ErrOperatorForbidden for every other caller, who requests the change
	// instead (Request).
	Admit(ctx context.Context, peer *identity.Peer, by wire.Subject) error
	// AdmitCompletion decides who completes the effect of an answered
	// question (ApplyFirstUseAllow, ApplyPermissionAllow): the service pins
	// the occurrence and derives every target from the person's answer. nil
	// admits; ErrOperatorForbidden refuses.
	AdmitCompletion(ctx context.Context, peer *identity.Peer, by wire.Subject) error
	// Apply applies an exempt caller's change at once and records it. It
	// rechecks the exemption; a caller no longer exempt is forbidden.
	Apply(ctx context.Context, peer *identity.Peer, by wire.Subject, change wire.PolicyChange) ChangeResult
	// Request applies an exempt caller's change at once, and otherwise admits
	// the person's question and waits up to wait for the answer.
	Request(ctx context.Context, peer *identity.Peer, by wire.Subject, change wire.PolicyChange, wait time.Duration) ChangeResult
	// Observe waits up to wait for one request by's program made to settle.
	Observe(ctx context.Context, by wire.Subject, id string, wait time.Duration) wire.ChangeRequestState
	// List reports the requests by's program made that the service holds.
	List(ctx context.Context, by wire.Subject) wire.ChangeRequestPage
}

// ChangeResult is a change request's state and, for an applied or
// conflicting change, the policy owner's own reply to the edit it made.
type ChangeResult struct {
	State   wire.ChangeRequestState
	Edit    *wire.PolicyEdit
	Default *wire.DefaultEdit
	Action  *wire.ActionEdit
}

// ErrChangeExempt is Admit's answer for an exempt caller.
var ErrChangeExempt = errors.New("rights: change applied through the exempt path")

// EnableOperatorChanges routes every operator edit through changes (RIGHTS-O17).
// Without it, every authorized operator edits directly.
func (h *Host) EnableOperatorChanges(changes OperatorChanges) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.serving || h.ctx.Err() != nil || changes == nil {
		return errors.New("rights: configure operator changes before Serve")
	}
	h.changes = changes
	return nil
}

// admitChange is authorize plus the change admission: the subject and nil for
// a direct edit, ErrChangeExempt for an exempt caller, or a refusal.
func (r *operatorReceiver) admitChange() (wire.Subject, *identity.Peer, error) {
	by, err := r.authorize()
	if err != nil {
		return wire.Subject{}, nil, err
	}
	_, peer, err := r.caller()
	if err != nil {
		return wire.Subject{}, nil, ErrOperatorForbidden
	}
	if r.host.changes == nil {
		return by, peer, nil
	}
	if err := r.host.changes.Admit(r.ctx, peer, by); err != nil {
		return by, peer, err
	}
	return by, peer, nil
}

// authorizeCompletion admits completing an answered question's effect.
func (r *operatorReceiver) authorizeCompletion() (wire.Subject, error) {
	by, err := r.authorize()
	if err != nil || r.host.changes == nil {
		return by, err
	}
	_, peer, err := r.caller()
	if err != nil {
		return wire.Subject{}, ErrOperatorForbidden
	}
	if err := r.host.changes.AdmitCompletion(r.ctx, peer, by); err != nil {
		return wire.Subject{}, err
	}
	return by, nil
}

// authorizeDirect admits only a direct edit: an edit with no typed request
// form is the Panel window's alone.
func (r *operatorReceiver) authorizeDirect() (wire.Subject, error) {
	by, _, err := r.admitChange()
	if errors.Is(err, ErrChangeExempt) {
		return wire.Subject{}, ErrOperatorForbidden
	}
	return by, err
}

// exempt applies an exempt caller's edit through the service, which records
// it. routed is false for a direct edit, which the caller then makes itself.
func (r *operatorReceiver) exempt(change wire.PolicyChange) (result ChangeResult, routed bool, err error) {
	by, peer, err := r.admitChange()
	if err == nil {
		return ChangeResult{}, false, nil
	}
	if !errors.Is(err, ErrChangeExempt) {
		return ChangeResult{}, true, err
	}
	return r.host.changes.Apply(r.ctx, peer, by, change), true, nil
}

func changeRefusal(outcome wire.ChangeRequestOutcome) wire.ChangeRequestState {
	return wire.ChangeRequestState{Outcome: outcome}
}

func changeOutcome(err error) wire.ChangeRequestOutcome {
	if errors.Is(err, ErrOperatorForbidden) {
		return wire.ChangeRequestOutcomeForbidden
	}
	return wire.ChangeRequestOutcomeUnavailable
}

// changeWait bounds a wait to the service's 0..30000 ms.
func changeWait(waitMS int64) (time.Duration, bool) {
	if waitMS < 0 || waitMS > 30000 {
		return 0, false
	}
	return time.Duration(waitMS) * time.Millisecond, true
}

func (r *operatorReceiver) RequestChange(change wire.PolicyChange, waitMS int64) (wire.ChangeRequestState, error) {
	wait, ok := changeWait(waitMS)
	if !ok {
		return changeRefusal(wire.ChangeRequestOutcomeInvalid), nil
	}
	by, err := r.authorize()
	if err != nil {
		return changeRefusal(changeOutcome(err)), nil
	}
	if r.host.changes == nil {
		return changeRefusal(wire.ChangeRequestOutcomeUnavailable), nil
	}
	_, peer, err := r.caller()
	if err != nil {
		return changeRefusal(wire.ChangeRequestOutcomeForbidden), nil
	}
	ctx := r.ctx
	if wait > 0 && r.observationContext != nil {
		ctx = r.observationContext()
	}
	return r.host.changes.Request(ctx, peer, by, change, wait).State, nil
}

func (r *operatorReceiver) ObserveChangeRequest(id string, waitMS int64) (wire.ChangeRequestState, error) {
	wait, ok := changeWait(waitMS)
	if !ok || id == "" || len(id) > 128 {
		return changeRefusal(wire.ChangeRequestOutcomeInvalid), nil
	}
	by, err := r.authorize()
	if err != nil {
		return changeRefusal(changeOutcome(err)), nil
	}
	if r.host.changes == nil {
		return changeRefusal(wire.ChangeRequestOutcomeUnavailable), nil
	}
	ctx := r.ctx
	if wait > 0 && r.observationContext != nil {
		ctx = r.observationContext()
	}
	state := r.host.changes.Observe(ctx, by, id, wait)
	if _, err := r.authorize(); err != nil {
		return changeRefusal(changeOutcome(err)), nil
	}
	return state, nil
}

func (r *operatorReceiver) ListChangeRequests() (wire.ChangeRequestPage, error) {
	refusal := func(outcome wire.PolicyPageOutcome) wire.ChangeRequestPage {
		return wire.ChangeRequestPage{Outcome: outcome, Requests: []wire.ChangeRequestState{}}
	}
	by, err := r.authorize()
	if err != nil {
		return refusal(operatorPageError(err)), nil
	}
	if r.host.changes == nil {
		return refusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	page := r.host.changes.List(r.ctx, by)
	if _, err := r.authorize(); err != nil {
		return refusal(operatorPageError(err)), nil
	}
	return page, nil
}

// policyEditOf is an exempt change's reply in the direct edit's shape.
func policyEditOf(result ChangeResult) wire.PolicyEdit {
	if result.Edit != nil {
		return *result.Edit
	}
	return wire.PolicyEdit{Outcome: policyEditOutcomeOf(result.State.Outcome)}
}

func defaultEditOf(result ChangeResult) wire.DefaultEdit {
	if result.Default != nil {
		return *result.Default
	}
	return wire.DefaultEdit{Outcome: policyEditOutcomeOf(result.State.Outcome)}
}

func actionEditOf(result ChangeResult) wire.ActionEdit {
	if result.Action != nil {
		return *result.Action
	}
	switch result.State.Outcome {
	case wire.ChangeRequestOutcomeInvalid:
		return wire.ActionEdit{Outcome: wire.ActionEditOutcomeInvalid}
	case wire.ChangeRequestOutcomeForbidden, wire.ChangeRequestOutcomeRefused, wire.ChangeRequestOutcomePending:
		return wire.ActionEdit{Outcome: wire.ActionEditOutcomeForbidden}
	}
	return wire.ActionEdit{Outcome: wire.ActionEditOutcomeUnavailable}
}

func policyEditOutcomeOf(outcome wire.ChangeRequestOutcome) wire.PolicyEditOutcome {
	switch outcome {
	case wire.ChangeRequestOutcomeInvalid:
		return wire.PolicyEditOutcomeInvalid
	case wire.ChangeRequestOutcomeForbidden, wire.ChangeRequestOutcomeRefused, wire.ChangeRequestOutcomePending:
		return wire.PolicyEditOutcomeForbidden
	}
	return wire.PolicyEditOutcomeUnavailable
}
