package rights

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

// The awake lease stays on the native service because its lifetime is the
// holder's connection. The generated profile carries one request per framed
// call under a bounded call deadline (5 s at the rights host); a hold carried
// by such a call ends at that deadline while the holder is still connected.
func TestAwakeLeaseNeedsConnectionLifetime(t *testing.T) {
	const callBound = 5 * time.Second // abstraction-rights/go/authorization/host.go call deadline

	h := start(t)
	var held atomic.Int32
	h.s.awake = func(who, why string) (func(), error) {
		held.Add(1)
		var once atomic.Bool
		return func() {
			if once.CompareAndSwap(false, true) {
				held.Add(-1)
			}
		}, nil
	}
	secret := registerApproved(t, h, "lease-lifetime")
	token, _, err := h.app.Ask(secret, RightAwake)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.app.Hold(token, "outliving one framed call")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lease.Done():
		t.Fatal("native lease ended before the framed call bound")
	case <-time.After(callBound + time.Second):
	}
	if held.Load() != 1 {
		t.Fatalf("native lease past the framed call bound holds %d requests", held.Load())
	}
	lease.Release()
	deadline := time.Now().Add(2 * time.Second)
	for held.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("closing the holder connection left the platform request held")
		}
		time.Sleep(10 * time.Millisecond)
	}

	at := endpoint(t, t.TempDir(), "framed-hold")
	l, err := listen.Listen(at)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	holdEnded := make(chan time.Duration, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			holdEnded <- -1
			return
		}
		callCtx, cancel := context.WithTimeout(context.Background(), callBound)
		defer cancel()
		call, err := listen.ReceiveFramed(callCtx, conn, listen.Program, 1<<16)
		if err != nil {
			holdEnded <- -1
			return
		}
		began := time.Now()
		<-call.WaitContext().Done() // a hold that lasts while the caller stays connected
		holdEnded <- time.Since(began)
		call.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	began := time.Now()
	_, err = listen.FrameClient{Endpoint: at, Timeout: 30 * time.Second}.ExchangeFrameContext(ctx, []byte(`{"hold":"awake"}`))
	caller := time.Since(began)
	if err == nil {
		t.Fatal("framed hold replied without the service ending it")
	}
	held_ := <-holdEnded
	if held_ < callBound-time.Second || held_ > callBound+2*time.Second {
		t.Fatalf("framed call hold lasted %v while the caller stayed connected", held_)
	}
	if caller > callBound+2*time.Second {
		t.Fatalf("connected caller outlived the framed call bound: %v", caller)
	}
	t.Logf("native lease held past %v until release; framed hold ended after %v with caller connected (%v)", callBound, held_, err)
}
