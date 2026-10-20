// Package gate is the decision seam a receiving service asks before it
// performs a gated operation for a caller it has bound.
//
// It sits beside the rights decision host and imports only the rights client,
// so a service such as the router or the resource table holds one Gate
// without linking the decision policy.
package gate

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strings"

	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-rights/go/client"
)

// A Gate decides one action on one resource for a caller a receiving service
// has bound. It returns nil to permit, an error wrapping ErrUnavailable when
// no decision could be obtained, and any other error to refuse. It must honor
// ctx and be safe for concurrent calls.
//
// A service designates each gate it installs for its own namespace with For,
// so the installed gate refuses every action outside that namespace
// (abstraction-rights RIGHTS-A7).
type Gate func(ctx context.Context, peer *identity.Peer, action, resource string) error

// ErrUnavailable marks a decision that could not be obtained. A service reads
// it as its contract's unavailable outcome, never as a permit and never as a
// refusal.
var ErrUnavailable = errors.New("rights gate: decision unavailable")

// errAbsent is the decision of a service nobody installed a gate on.
var errAbsent = fmt.Errorf("%w: no gate installed", ErrUnavailable)

// Check asks g for one operation. A service with no gate installed holds a
// nil Gate, and a missing policy follows its contract default, never universal
// Allow (ARCHITECTURE.md): Check on a nil gate returns ErrUnavailable. A nil
// peer and a context that ends before or during the decision also return
// ErrUnavailable, because a decision the service cannot evaluate refuses
// (abstraction-rights RIGHTS-R26).
func (g Gate) Check(ctx context.Context, peer *identity.Peer, action, resource string) error {
	if g == nil {
		return errAbsent
	}
	if peer == nil {
		return fmt.Errorf("%w: caller not bound", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	err := g(ctx, peer, action, resource)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ErrUnavailable, ctxErr)
	}
	return err
}

// For designates g for one namespace (RIGHTS-A7): the returned gate refuses
// every action outside namespace and asks g for every action in it.
// namespace is an action prefix such as "abstraction.router"; an action is in
// it when it begins with namespace followed by "/". A service applies For to
// each gate it installs, so a gate that would permit anything still decides
// only the service's own actions.
func For(namespace string, g Gate) (Gate, error) {
	if namespace == "" || strings.Contains(namespace, "/") {
		return nil, fmt.Errorf("rights gate: namespace %q is not one action namespace", namespace)
	}
	if g == nil {
		return nil, errors.New("rights gate: no gate to designate")
	}
	prefix := namespace + "/"
	return func(ctx context.Context, peer *identity.Peer, action, resource string) error {
		if !strings.HasPrefix(action, prefix) {
			return fmt.Errorf("rights gate: %s is outside %s", action, namespace)
		}
		return g(ctx, peer, action, resource)
	}, nil
}

// Local returns the explicit gate of a service that runs without the rights
// service, designated for namespace with For. It permits a caller under the
// service's own account, refuses a caller under any other account, and
// returns ErrUnavailable for a caller whose account cannot be named
// (RIGHTS-R26).
func Local(namespace string) (Gate, error) {
	owner, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("rights gate: service account unavailable: %w", err)
	}
	if owner.Uid == "" {
		return nil, errors.New("rights gate: service account unavailable")
	}
	return For(namespace, account(owner.Uid))
}

// account permits a caller under the named account and refuses every other.
func account(owner string) Gate {
	return func(_ context.Context, peer *identity.Peer, _, _ string) error {
		subject, err := client.SubjectFromPeer(peer)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		if subject.Account != owner {
			return errors.New("rights gate: caller runs under another account")
		}
		return nil
	}
}
