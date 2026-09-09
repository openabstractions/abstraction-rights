package rights

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	job "github.com/openabstractions/abstraction-job/go"
	watch "github.com/openabstractions/abstraction-watch/go"
)

func claimed(t *testing.T, s job.Store) *job.Record {
	t.Helper()
	id, err := s.Submit(job.Record{Kind: "encode", Spec: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Claim(id, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func awaitLetGo(t *testing.T, h *job.Hold) {
	t.Helper()
	sub := watch.Poll(func() ([]bool, string, error) {
		held := h.Held()
		return []bool{held}, fmt.Sprint(held), nil
	}, 10*time.Millisecond, 0)
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for h.Held() {
		if _, err := sub.Next(ctx); err != nil {
			t.Fatalf("still held: %v", err)
		}
	}
}

func TestAJobAsksBeforeItHolds(t *testing.T) {
	h := start(t)
	platform := make(chan string, 4)
	h.s.awake = func(who, why string) (func(), error) {
		platform <- who + ": " + why
		return func() {}, nil
	}
	secret := registerApproved(t, h, "demo")
	reg := &Registration{Client: h.app, Secret: secret}
	s := job.NewMemoryStore()
	rec := claimed(t, s)

	hold := job.KeepAwakeVia(reg, s, rec)
	if !hold.Held() || hold.Why() != nil {
		t.Fatalf("granted: held=%v, why=%v", hold.Held(), hold.Why())
	}
	why := "worker-a: encode " + rec.ID
	select {
	case got := <-platform:
		if got != "demo: "+why {
			t.Fatalf("the platform was told %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the service was never asked to hold")
	}
	holds, err := h.tool.Holds()
	if err != nil || len(holds) != 1 || holds[0].Name != "demo" || holds[0].Right != RightAwake || holds[0].Why != why {
		t.Fatalf("rights holds = %+v, %v", holds, err)
	}
	t.Logf("rights holds: app=%s right=%s why=%q since=%s seen=%s", holds[0].Name, holds[0].Right, holds[0].Why, holds[0].Since.Format(time.RFC3339), holds[0].Seen)

	if err := h.tool.Revoke("demo", RightAwake); err != nil {
		t.Fatal(err)
	}
	awaitLetGo(t, hold)
	if !errors.Is(hold.Why(), job.ErrTakenAway) {
		t.Fatalf("revoked: why=%v", hold.Why())
	}
	hold.Release()
	if holds, _ := h.tool.Holds(); len(holds) != 0 {
		t.Fatalf("after revoke, rights holds = %+v", holds)
	}

	again := job.KeepAwakeVia(reg, s, rec)
	if again.Held() || again.Why() == nil || again.Why().Error() != ErrNotGranted.Error() {
		t.Fatalf("not granted: held=%v, why=%v", again.Held(), again.Why())
	}
	t.Logf("refused after revoke: why=%v", again.Why())
	if len(platform) != 0 {
		t.Fatal("the platform was asked for a hold the service refused")
	}

	unknown := job.KeepAwakeVia(&Registration{Client: h.app, Secret: "not-a-secret"}, s, rec)
	if unknown.Held() || unknown.Why() == nil || unknown.Why().Error() != ErrBadSecret.Error() {
		t.Fatalf("unknown application: held=%v, why=%v", unknown.Held(), unknown.Why())
	}
	t.Logf("refused, unknown application: why=%v", unknown.Why())
}

func TestNoServiceMeansThePlatformHolds(t *testing.T) {
	reg := &Registration{Client: &Client{Endpoint: endpoint(t, t.TempDir(), "rights")}, Secret: "whatever"}
	_, err := reg.Hold("worker-a", "encode x")
	if !errors.Is(err, job.ErrAbsent) {
		t.Fatalf("nobody listening: %v", err)
	}
	t.Logf("nobody listening: %v", err)
	s := job.NewMemoryStore()
	hold := job.KeepAwakeVia(reg, s, claimed(t, s))
	defer hold.Release()
	switch refused := job.CanKeepAwake(); {
	case refused == nil && (!hold.Held() || hold.Why() != nil):
		t.Fatalf("this machine can be kept awake: held=%v, why=%v", hold.Held(), hold.Why())
	case refused != nil && (hold.Held() || hold.Why() == nil || errors.Is(hold.Why(), job.ErrAbsent)):
		t.Fatalf("this machine refuses to be kept awake (%v): held=%v, why=%v", refused, hold.Held(), hold.Why())
	}
	t.Logf("no service: held=%v why=%v", hold.Held(), hold.Why())
}

func TestAStoppedServiceTakesItsHoldsWithIt(t *testing.T) {
	h := start(t)
	h.s.awake = func(who, why string) (func(), error) { return func() {}, nil }
	secret := registerApproved(t, h, "demo")
	s := job.NewMemoryStore()
	hold := job.KeepAwakeVia(&Registration{Client: h.app, Secret: secret}, s, claimed(t, s))
	if !hold.Held() {
		t.Fatalf("granted: why=%v", hold.Why())
	}
	h.s.Close()
	awaitLetGo(t, hold)
	if !errors.Is(hold.Why(), job.ErrTakenAway) {
		t.Fatalf("service stopped: why=%v", hold.Why())
	}
	hold.Release()
}
