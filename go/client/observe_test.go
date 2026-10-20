package client

import (
	"context"
	"fmt"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type observationProvider struct {
	wire.AuthorizationOperator
	observe func(string, int64) (wire.PolicyObservation, error)
}

func (p observationProvider) ObservePolicy(after string, wait int64) (wire.PolicyObservation, error) {
	return p.observe(after, wait)
}

var observationFixtureSerial atomic.Uint64

// Exchange real generated frames through native receiving proof. Semantically
// forged replies must not advance the wrapper's resume cursor or leak revision.
func TestObservePolicyPagesValidateRefuseAndResume(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("native Program proof is not implemented on macOS")
	}
	endpoint := listen.Endpoint(fmt.Sprintf("rights-client-observe-%d-%d", os.Getpid(), observationFixtureSerial.Add(1)))
	l, err := listen.ListenFramed(endpoint, listen.Program)
	if err != nil {
		t.Fatal(err)
	}
	l = listen.Sessions(l, listen.SessionOptions{MaxSessions: 4})
	defer l.Close()
	pages := []wire.PolicyObservation{
		{Outcome: wire.PolicyObservationOutcomeChanged, Next: "valid", Revision: "revision", Mechanism: wire.PolicyObservationMechanismNative},
		{Outcome: wire.PolicyObservationOutcomeUnchanged, Next: "poison", Revision: "revision", Mechanism: wire.PolicyObservationMechanismNative},
		{Outcome: wire.PolicyObservationOutcomeGap, Next: "valid", Mechanism: wire.PolicyObservationMechanismNative},
		{Outcome: wire.PolicyObservationOutcomeForbidden, Revision: "leaked", Mechanism: wire.PolicyObservationMechanismNative},
		{Outcome: wire.PolicyObservationOutcomeUnavailable, Mechanism: wire.PolicyObservationMechanismNative},
	}
	wantAfter := []string{"", "valid", "valid", "valid", "valid"}
	done := make(chan error, 1)
	go func() {
		for i := range pages {
			conn, e := l.Accept()
			if e != nil {
				done <- e
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			call, e := listen.ReceiveFramed(ctx, conn, identity.Need{User: identity.ProofKernel, Process: identity.ProofPID, Path: identity.ProofPID}, 1<<20)
			if e == nil {
				d := wire.AuthorizationOperatorDispatcher{Handler: observationProvider{observe: func(after string, wait int64) (wire.PolicyObservation, error) {
					if after != wantAfter[i] || wait != 0 {
						t.Errorf("request %d after=%q wait=%d", i, after, wait)
					}
					return pages[i], nil
				}}}
				var reply []byte
				reply, e = d.ExchangeFrame(call.Frame)
				if e == nil {
					e = call.Reply(reply)
				}
				call.Close()
			} else {
				conn.Close()
			}
			cancel()
			if e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	seq := NewOperator(endpoint).ObservePolicyPagesContext(context.Background(), "", 0)
	n := 0
	seq(func(page PolicyObservation, e error) bool {
		n++
		if n == 1 {
			if e != nil || page.Next != "valid" {
				t.Fatal(page, e)
			}
			return true
		}
		if e == nil || page.Next != "" || page.Revision != "" {
			t.Fatal("forged page escaped", page, e)
		}
		return true
	})
	if n != 2 {
		t.Fatal(n)
	}
	seq(func(page PolicyObservation, e error) bool {
		if e != nil || page.Outcome != wire.PolicyObservationOutcomeGap {
			t.Fatal(page, e)
		}
		return true
	})
	seq(func(page PolicyObservation, e error) bool {
		if e == nil || page.Revision != "" {
			t.Fatal("forged refusal escaped", page, e)
		}
		return true
	})
	seq(func(page PolicyObservation, e error) bool {
		if e != nil || page.Outcome != wire.PolicyObservationOutcomeUnavailable {
			t.Fatal(page, e)
		}
		return true
	})
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
