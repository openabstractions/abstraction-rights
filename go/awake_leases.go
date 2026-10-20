package rights

import "time"

// WakeKeeper is the connection bridge supplied by the composing host. Rights
// checks its rule first and supplies the authenticated original subject.
type WakeKeeper interface {
	KeepAwake(program, account, why string) (lease string, release func(), err error)
}

// WakeFactory constructs the owner before the legacy service accepts callers.
type WakeFactory func() (WakeKeeper, error)

// AwakeLeases preserves the published external listing seam. The rights
// service owns the authenticated connection and ends its resource-book hold
// when that connection ends or its rule is revoked. The resource book owns
// the platform request. Standalone Start retains its compatibility fallback.
// A supplied listing receives the same original program and account.
type AwakeLeases interface {
	// HoldAwake writes one connection-owned lease of resource awake for a
	// holder this service has already decided the rule for, and returns its
	// id and the release that ends it.
	HoldAwake(program, account, why string) (lease string, release func())
	// AwakeHolds is the table's awake rows, oldest first.
	AwakeHolds() []AwakeHold
}

// An AwakeHold is one row of the table's awake resource.
type AwakeHold struct {
	Lease   string
	Program string
	Account string
	Why     string
	Since   time.Time
}

// UseLeases writes this service's wake holds into the resource lease book, and
// reads them back from there. Configure it before the first hold.
//
// Without one the service keeps its own listing, which is what a standalone
// `openabstractions serve rights` does: there is no resource table in that
// process to write a row into, and a hold nobody can read is worse than a
// listing nobody composed.
func (s *Service) UseLeases(book AwakeLeases) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases = book
}
