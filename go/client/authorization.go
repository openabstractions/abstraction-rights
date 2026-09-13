// Package client binds an explicitly selected rights decision service.
package client

import (
	"context"
	"errors"
	"fmt"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"path/filepath"
	"strconv"
	"time"
)

type Subject = wire.Subject
type Decision = wire.Decision
type Client struct{ transport listen.FrameClient }

func New(endpoint string) *Client {
	return NewWithTransport(listen.FrameClient{Endpoint: endpoint})
}

// NewWithTransport retains the caller's endpoint, server trust and waiting limits.
func NewWithTransport(transport listen.FrameClient) *Client {
	return &Client{transport: transport.WithDefaults(5*time.Second, 1<<20)}
}

// SubjectFromPeer requires Program proof supplied by a receiving service. Its
// serialized result remains an attributed assertion at the decision service.
func SubjectFromPeer(peer *identity.Peer) (Subject, error) {
	if peer == nil {
		return Subject{}, errors.New("rights: native subject evidence required")
	}
	if e := peer.Check(listen.Program); e != nil {
		return Subject{}, e
	}
	u, e := peer.User.AtLeast(listen.Program.User)
	if e != nil {
		return Subject{}, e
	}
	account := ""
	if u.Kind == "windows" {
		account = u.SID
	} else if u.Kind == "posix" && u.UID >= 0 {
		account = strconv.Itoa(u.UID)
	}
	program, e := peer.Path.AtLeast(listen.Program.Path)
	if e != nil || account == "" || !filepath.IsAbs(program) {
		return Subject{}, errors.New("rights: native subject account/program unavailable")
	}
	return Subject{Account: account, Program: filepath.Clean(program)}, nil
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
	evaluated := false
	switch v.Outcome {
	case wire.DecisionOutcomePermitted, wire.DecisionOutcomeDenied, wire.DecisionOutcomeNotGranted, wire.DecisionOutcomeUnknownAction:
		evaluated = true
	case wire.DecisionOutcomeInvalid, wire.DecisionOutcomeForbidden, wire.DecisionOutcomeUnavailable:
	default:
		return Decision{}, errors.New("rights: unknown decision outcome")
	}
	if evaluated != (v.PolicyRevision != "") {
		return Decision{}, errors.New("rights: inconsistent decision revision")
	}
	return v, nil
}

var ErrNotPermitted = errors.New("rights: not permitted")

type DecisionError struct {
	Outcome        string
	PolicyRevision string
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
		return &DecisionError{v.Outcome, v.PolicyRevision}
	}
	return nil
}
