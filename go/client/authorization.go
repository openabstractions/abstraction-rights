// Package client binds an explicitly selected rights decision service.
package client

import (
	"context"
	"errors"
	"fmt"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"time"
)

type Subject = wire.Subject
type Decision = wire.Decision
type RevisionDecision = wire.RevisionDecision
type Client struct{ transport listen.FrameClient }

func New(endpoint string) *Client {
	return NewWithTransport(listen.FrameClient{Endpoint: endpoint})
}

// NewWithTransport retains the caller's endpoint, server trust and waiting limits.
func NewWithTransport(transport listen.FrameClient) *Client {
	return &Client{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}

// SubjectFromPeer is identity.SubjectOf at listen.Program, the proof a
// receiving service requires, in this contract's Subject. Its serialized
// result remains an attributed assertion at the decision service.
func SubjectFromPeer(peer *identity.Peer) (Subject, error) {
	s, e := identity.SubjectOf(peer, listen.Program)
	if e != nil {
		return Subject{}, e
	}
	return Subject{Account: s.Account, Program: s.Program}, nil
}
func (c *Client) DecideContext(ctx context.Context, action, resource string) (Decision, error) {
	if e := ctx.Err(); e != nil {
		return Decision{}, e
	}
	v, e := wire.NewAuthorizationClient(c.transport.WithContext(ctx)).Decide(action, resource)
	return checked(v, e)
}
func (c *Client) DecideForContext(ctx context.Context, subject Subject, action, resource string) (Decision, error) {
	if e := ctx.Err(); e != nil {
		return Decision{}, e
	}
	v, e := wire.NewAuthorizationClient(c.transport.WithContext(ctx)).DecideFor(subject, action, resource)
	return checked(v, e)
}
func checked(v Decision, e error) (Decision, error) {
	if e != nil {
		return Decision{}, e
	}
	if _, valid := v.Outcome.WireName(); !valid {
		return Decision{}, errors.New("rights: unknown decision outcome")
	}
	if Evaluated(v.Outcome) != (v.PolicyRevision != "") {
		return Decision{}, errors.New("rights: inconsistent decision revision")
	}
	return v, nil
}

// DecideForAtLeastRevisionContext never falls back to a method without minimum.
func (c *Client) DecideForAtLeastRevisionContext(ctx context.Context, subject Subject, action, resource, minimum string) (wire.RevisionDecision, error) {
	if e := ctx.Err(); e != nil {
		return wire.RevisionDecision{}, e
	}
	v, e := wire.NewAuthorizationClient(c.transport.WithContext(ctx)).DecideForAtLeastRevision(subject, action, resource, minimum)
	if e != nil {
		return wire.RevisionDecision{}, e
	}
	d, e := checked(v.Decision, nil)
	if e != nil {
		return wire.RevisionDecision{}, e
	}
	if (d.PolicyRevision != "") != (v.ObservedRevision != "") || len(v.ObservedRevision) > 128 {
		return wire.RevisionDecision{}, errors.New("rights: inconsistent freshness observation")
	}
	return v, nil
}

var ErrNotPermitted = errors.New("rights: not permitted")

// Evaluated reports a policy decision carrying a policy revision. Boundary
// errors and unknown enum values carry no policy decision. Only permitted
// authorizes access; an evaluated refusal still refuses.
func Evaluated(outcome wire.DecisionOutcome) bool {
	switch outcome {
	case wire.DecisionOutcomePermitted, wire.DecisionOutcomeDenied, wire.DecisionOutcomeNotGranted, wire.DecisionOutcomeUnknownAction:
		return true
	}
	return false
}

// PermittedOrNotGranted reports a known permit or a missing grant. A caller
// may continue to its separate admission checks in either case. Only a
// permitted outcome authorizes access through Rights itself.
func PermittedOrNotGranted(outcome wire.DecisionOutcome) bool {
	switch outcome {
	case wire.DecisionOutcomePermitted, wire.DecisionOutcomeNotGranted:
		return true
	default:
		return false
	}
}

type DecisionError struct {
	Outcome        string
	PolicyRevision string
}

// DecisionOutcome reads the generated outcome vocabulary from the published
// string field. An unrecognized word returns the enum's invalid zero value.
func (e *DecisionError) DecisionOutcome() wire.DecisionOutcome {
	if e == nil {
		return 0
	}
	outcome, _ := wire.ParseDecisionOutcome(e.Outcome)
	return outcome
}

func (e *DecisionError) Error() string {
	return fmt.Sprintf("rights: %s (policy %s)", e.Outcome, e.PolicyRevision)
}
func (e *DecisionError) Unwrap() error { return ErrNotPermitted }

// Require is a native enforcement helper. Only the decision point's permitted
// result succeeds. Every refusal or transport failure stops resource access.
func (c *Client) Require(ctx context.Context, peer *identity.Peer, action, resource string) error {
	subject, e := SubjectFromPeer(peer)
	if e != nil {
		return e
	}
	v, e := c.DecideForContext(ctx, subject, action, resource)
	if e != nil {
		return e
	}
	if v.Outcome != wire.DecisionOutcomePermitted {
		return &DecisionError{v.Outcome.String(), v.PolicyRevision}
	}
	return nil
}
