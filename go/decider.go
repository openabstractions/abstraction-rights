package rights

import (
	"context"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
)

// Require decides one exact rule in this process for the caller a receiving
// service bound, with the same result shape as client.Client.Require: nil for
// permitted, a *client.DecisionError for every other decision outcome, and the
// evidence error when the peer carries no Program proof. The subject comes from
// client.SubjectFromPeer. Each call reads the policy file afresh; no decision is
// cached. A host that serves its own resource services decides through this
// method and needs no enforcer designation.
func (p *DecisionPolicy) Require(ctx context.Context, peer *identity.Peer, action, resource string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	subject, err := client.SubjectFromPeer(peer)
	if err != nil {
		return err
	}
	decision := p.DecideContext(ctx, subject, action, resource)
	if decision.Outcome != wire.DecisionOutcomePermitted {
		return &client.DecisionError{Outcome: decision.Outcome.String(), PolicyRevision: decision.PolicyRevision}
	}
	return nil
}
