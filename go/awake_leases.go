package rights

import "time"

// The wake hold moved under abstraction.resource/leases@1 in the release that
// ships the resource contract (abstraction-resource CONTRACT.md RES-A1). Two
// halves of it live in two places, and this file is the seam.
//
// The lifetime stayed here. The platform request is released when the holder
// closes, exits or is killed, and a request-response profile carries one call
// under a bounded deadline, so a hold carried by such a call would end at that
// deadline while the holder was still connected (CONTRACT.md,
// go/awake_lease_test.go). This service owns the holder's connection, so it
// keeps the request.
//
// The record moved. Who holds the machine awake, since when and under which
// rule is a row of the resource table now, so one reader answers who holds the
// card and who holds the wake. `rights holds` reads those rows through this
// seam rather than a listing of its own.

// An AwakeLeases is the resource service's lease book, seen from here. The
// resource module is not imported: this service decides rights, and a
// decision layer that had to import the layer above it would be the wrong way
// round. A composition that serves both wires one to the other.
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
