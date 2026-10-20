package rights

import (
	"context"

	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
)

// A decision's context carries the peer the receiving service bound for it,
// so a host class can read what the transport proved about the caller. No
// request payload reaches it: only code holding the bound *identity.Peer can
// attach one.

type boundPeerKey struct{}

// WithBoundPeer returns ctx carrying peer, the peer a receiving service bound
// for the decisions made under ctx. A nil peer returns ctx unchanged.
func WithBoundPeer(ctx context.Context, peer *identity.Peer) context.Context {
	if peer == nil {
		return ctx
	}
	return context.WithValue(ctx, boundPeerKey{}, peer)
}

// BoundPeer returns the peer WithBoundPeer attached to ctx, or nil.
func BoundPeer(ctx context.Context) *identity.Peer {
	if ctx == nil {
		return nil
	}
	peer, _ := ctx.Value(boundPeerKey{}).(*identity.Peer)
	return peer
}

// ElevatedCaller reports whether ctx's bound peer binds exactly the subject s
// and elevated classifies it as elevated: an elevated local native peer of
// s's own account (RIGHTS-R27). A nil elevated is identity's bound attribute,
// (*identity.Peer).Elevated. A peer that binds another subject, or none, is
// no evidence about s.
func ElevatedCaller(ctx context.Context, s wire.Subject, elevated func(*identity.Peer) bool) bool {
	peer := BoundPeer(ctx)
	if peer == nil {
		return false
	}
	if elevated == nil {
		elevated = (*identity.Peer).Elevated
	}
	if !elevated(peer) {
		return false
	}
	bound, err := client.SubjectFromPeer(peer)
	if err != nil {
		return false
	}
	normalized, err := NormalizeDecisionSubject(wire.Subject{Account: bound.Account, Program: bound.Program})
	want, wantErr := NormalizeDecisionSubject(s)
	return err == nil && wantErr == nil && !remoteSubject(want) && normalized == want
}

// ElevatedCallersDefault is the elevated-callers default (RIGHTS-R27): one
// switch, on after a fresh install, that permits every registered action on
// every resource for an elevated local native peer of the runtime's own
// account, script hosts included. elevated classifies the bound peer; nil is
// identity's own attribute. It writes no rule; a person's own rule or Block
// for the program still decides first.
func ElevatedCallersDefault(elevated func(*identity.Peer) bool) AccountDefault {
	return AccountDefault{Name: DefaultElevatedCallers, EveryAction: true, EveryResource: true, AllPrograms: true,
		Covers: func(ctx context.Context, s wire.Subject, _ string) bool { return ElevatedCaller(ctx, s, elevated) }}
}
