package authorization

import (
	"context"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
)

type receiver struct {
	host *Host
	call *listen.FramedCall
	ctx  context.Context
}

func (r *receiver) caller() (wire.Subject, *identity.Peer, error) {
	p, e := r.call.Peer()
	if e != nil {
		return wire.Subject{}, nil, e
	}
	s, e := client.SubjectFromPeer(p)
	return s, p, e
}
func (r *receiver) Decide(action, resource string) (wire.Decision, error) {
	s, _, e := r.caller()
	if e != nil || s.Account != r.host.owner {
		return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
	}
	return r.host.policy.Decide(s, action, resource), nil
}
func (r *receiver) DecideFor(subject wire.Subject, action, resource string) (wire.Decision, error) {
	s, peer, e := r.caller()
	if e != nil || s.Account != r.host.owner || subject.Account != r.host.owner || r.host.enforcer == nil {
		return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
	}
	if !r.host.enforcer(r.ctx, peer, action, resource) {
		return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
	}
	if e = r.ctx.Err(); e != nil {
		return wire.Decision{}, e
	}
	if e = r.call.Recheck(); e != nil {
		return wire.Decision{Outcome: wire.DecisionOutcomeForbidden}, nil
	}
	return r.host.policy.Decide(subject, action, resource), nil
}
