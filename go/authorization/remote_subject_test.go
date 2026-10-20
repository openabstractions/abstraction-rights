package authorization

import (
	"context"
	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
	"strings"
	"testing"
)

func TestRemoteSubjectNativeRelayRequiresDesignatedEnforcer(t *testing.T) {
	for _, mode := range []string{"nil", "refuse", "permit"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := policy(t)
			native := nativeSubject(t)
			s := wire.Subject{Account: native.Account, Program: "remote:" + strings.Repeat("a", 64)}
			if e := p.Set(s, action, "content", true); e != nil {
				t.Fatal(e)
			}
			var enforcer AuthorizeEnforcer
			if mode != "nil" {
				enforcer = func(_ context.Context, peer *identity.Peer, a, r string) bool {
					caller, e := client.SubjectFromPeer(peer)
					return mode == "permit" && e == nil && caller == native && a == action && r == "content"
				}
			}
			c, _ := live(t, p, enforcer)
			v, e := c.DecideForContext(context.Background(), s, action, "content")
			want := wire.DecisionOutcomeForbidden
			if mode == "permit" {
				want = wire.DecisionOutcomePermitted
			}
			if e != nil || v.Outcome != want {
				t.Fatal(v, e)
			}
			s.Account = "foreign"
			v, e = c.DecideForContext(context.Background(), s, action, "content")
			if e != nil || v.Outcome != wire.DecisionOutcomeForbidden {
				t.Fatal("foreign account admitted", v, e)
			}
		})
	}
}
