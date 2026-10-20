package client

import (
	"context"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// ObservePolicyContext receives one bounded invalidation under operator proof.
// Expiry can change the cursor while revision stays unchanged; ReadRule remains
// the confirmation of expiry. Transport trust and timeout retain caller limits.
func (c *Operator) ObservePolicyContext(ctx context.Context, after string, waitMS int64) (PolicyObservation, error) {
	var result PolicyObservation
	var err error
	c.ObservePolicyPagesContext(ctx, after, waitMS)(func(page PolicyObservation, e error) bool { result, err = page, e; return false })
	return result, err
}

// ObservePolicyPagesContext delegates generated pages with semantic validation.
// Refusals and errors are delivered once and end this invocation. Reentry uses
// only a validated successful cursor. A gap needs a new empty-cursor sequence;
// watch.Follow owns that restart and its presenter cancellation/join.
func (c *Operator) ObservePolicyPagesContext(ctx context.Context, after string, waitMS int64) func(func(PolicyObservation, error) bool) {
	return func(yield func(PolicyObservation, error) bool) {
		if e := ctx.Err(); e != nil {
			yield(PolicyObservation{}, e)
			return
		}
		if waitMS < 0 || waitMS > 30000 || (after != "" && !boundedOperatorString(after, 256)) {
			yield(PolicyObservation{}, errors.New("rights: invalid policy observation bounds"))
			return
		}
		wire.NewAuthorizationOperatorClient(c.transport.WithContext(ctx)).ObservePolicyPages(after, waitMS)(func(page PolicyObservation, e error) bool {
			if e != nil {
				yield(PolicyObservation{}, e)
				return false
			}
			valid := page.Mechanism == wire.PolicyObservationMechanismNative
			switch page.Outcome {
			case wire.PolicyObservationOutcomeChanged:
				valid = valid && boundedOperatorString(page.Revision, 128) && boundedOperatorString(page.Next, 256) && page.Next != after
			case wire.PolicyObservationOutcomeUnchanged:
				valid = valid && after != "" && page.Next == after && boundedOperatorString(page.Revision, 128)
			case wire.PolicyObservationOutcomeGap:
				valid = valid && after != "" && page.Next == after && page.Revision == ""
			default:
				valid = valid && page.Next == "" && page.Revision == ""
			}
			if !valid {
				yield(PolicyObservation{}, errors.New("rights: malformed policy observation"))
				return false
			}
			live := page.Outcome == wire.PolicyObservationOutcomeChanged || page.Outcome == wire.PolicyObservationOutcomeUnchanged
			if live {
				after = page.Next
			}
			return yield(page, nil) && live
		})
	}
}
