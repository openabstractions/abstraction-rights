package rights

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// The old word and the exact rule name one decision, so a rule already
// written and a Panel already reading it keep working.
func TestTheOldRightNameAndTheRuleAreOneDecision(t *testing.T) {
	action, resource, ok := Alias(RightAwake)
	if !ok || action != AwakeAction || resource != AwakeResource {
		t.Fatalf("Alias(%q) = %q %q %v", RightAwake, action, resource, ok)
	}
	if right, ok := RightOf(AwakeAction, AwakeResource); !ok || right != RightAwake {
		t.Fatalf("RightOf(%q,%q) = %q %v", AwakeAction, AwakeResource, right, ok)
	}
	if _, _, ok := Alias("wake"); ok {
		t.Fatal("a word this service never took is aliased to a rule")
	}
	if _, ok := RightOf("abstraction.resource/hold", "card:0"); ok {
		t.Fatal("holding the card was aliased to the wake right")
	}
}

// book is a lease book the test drives, standing for the resource service's.
type book struct {
	mu    sync.Mutex
	next  int
	holds map[string]AwakeHold
}

func newBook() *book { return &book{holds: map[string]AwakeHold{}} }

func (b *book) HoldAwake(program, account, why string) (string, func()) {
	b.mu.Lock()
	b.next++
	lease := "awake-" + string(rune('0'+b.next))
	b.holds[lease] = AwakeHold{Lease: lease, Program: program, Account: account, Why: why, Since: time.Now()}
	b.mu.Unlock()
	return lease, func() {
		b.mu.Lock()
		delete(b.holds, lease)
		b.mu.Unlock()
	}
}

func (b *book) AwakeHolds() []AwakeHold {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []AwakeHold{}
	for _, hold := range b.holds {
		out = append(out, hold)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lease < out[j].Lease })
	return out
}

// A hold becomes a row of the resource table's awake resource, and `rights
// holds` reads that row: one reader answers who holds the wake. The platform
// request stays on the holder's connection, which is the half that did not
// move.
func TestAWakeHoldBecomesALeaseAndHoldsReadsItBack(t *testing.T) {
	h := start(t)
	requests := make(chan struct{}, 4)
	h.s.awake = func(string, string) (func(), error) {
		requests <- struct{}{}
		return func() { <-requests }, nil
	}
	b := newBook()
	h.s.UseLeases(b)

	secret := registerApproved(t, h, "downloader")
	token, _, err := h.app.Ask(secret, RightAwake)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.app.Hold(token, "a six-hour download")
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var rows []AwakeHold
	for {
		if rows = b.AwakeHolds(); len(rows) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hold never became a row of the awake resource: %+v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rows[0].Why != "a six-hour download" || rows[0].Program == "" {
		t.Fatalf("the awake row is %+v", rows[0])
	}

	holds, err := h.tool.Holds()
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 1 {
		t.Fatalf("holds %+v", holds)
	}
	if holds[0].Lease != rows[0].Lease {
		t.Fatalf("holds read %q and the table's row is %q", holds[0].Lease, rows[0].Lease)
	}
	if holds[0].Right != RightAwake || holds[0].Name != "downloader" {
		t.Fatalf("the hold lost its registration: %+v", holds[0])
	}

	lease.Release()
	for deadline = time.Now().Add(5 * time.Second); len(b.AwakeHolds()) != 0; {
		if time.Now().After(deadline) {
			t.Fatal("closing the holder's connection left the row in the table")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if holds, err = h.tool.Holds(); err != nil || len(holds) != 0 {
		t.Fatalf("holds %+v %v", holds, err)
	}
}

// Without a lease book the service keeps its own listing, which is what a
// standalone rights host does.
func TestWithoutALeaseBookTheServiceKeepsItsOwnListing(t *testing.T) {
	h := start(t)
	h.s.awake = func(string, string) (func(), error) { return func() {}, nil }
	secret := registerApproved(t, h, "downloader")
	token, _, err := h.app.Ask(secret, RightAwake)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.app.Hold(token, "no table here")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	holds, err := h.tool.Holds()
	if err != nil || len(holds) != 1 {
		t.Fatalf("holds %+v %v", holds, err)
	}
	if holds[0].Lease != "" {
		t.Fatalf("a service with no table reported lease %q", holds[0].Lease)
	}
}
