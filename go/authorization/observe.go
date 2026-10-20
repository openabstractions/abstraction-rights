package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	watch "github.com/openabstractions/abstraction-watch/go"
	"github.com/openabstractions/abstraction-watch/go/cursor"
	"time"
	"unicode/utf8"
)

func (r *operatorReceiver) ObservePolicy(after string, waitMS int64) (wire.PolicyObservation, error) {
	if r.observationContext != nil {
		copy := *r
		copy.ctx = r.observationContext()
		r = &copy
	}
	refusal := func(outcome wire.PolicyObservationOutcome) (wire.PolicyObservation, error) {
		next := ""
		if outcome == wire.PolicyObservationOutcomeGap {
			next = after
		}
		return wire.PolicyObservation{Outcome: outcome, Next: next, Mechanism: wire.PolicyObservationMechanismNative}, nil
	}
	authorityOutcome := func(e error) wire.PolicyObservationOutcome {
		if errors.Is(e, ErrOperatorForbidden) {
			return wire.PolicyObservationOutcomeForbidden
		}
		return wire.PolicyObservationOutcomeUnavailable
	}
	subject, err := r.authorize()
	if err != nil {
		return refusal(authorityOutcome(err))
	}
	if waitMS < 0 || waitMS > 30000 || len(after) > 256 || !utf8.ValidString(after) {
		return refusal(wire.PolicyObservationOutcomeInvalid)
	}
	scope, _ := json.Marshal(subject)
	bound := sha256.Sum256(scope)
	codec := cursor.Codec{Separator: ":", Scoped: true}
	binding := hex.EncodeToString(bound[:])
	if after != "" {
		envelope, ok := codec.Parse(after)
		if !ok || !envelope.Hex(16, 32, 32) {
			return refusal(wire.PolicyObservationOutcomeInvalid)
		}
		if !envelope.Bound(r.host.operatorEpoch, binding) {
			return refusal(wire.PolicyObservationOutcomeGap)
		}
	}
	var answer wire.PolicyObservation
	var deadline time.Time
	outcome, err := r.host.observationGate.Wait(r.ctx, time.Duration(waitMS)*time.Millisecond, watch.Probe{
		Read: func() (bool, error) {
			state, e := r.host.policy.ObservePolicyStateContext(r.ctx)
			if e != nil {
				return false, e
			}
			deadline = state.Deadline
			answer = wire.PolicyObservation{Outcome: wire.PolicyObservationOutcomeChanged, Next: codec.Encode(cursor.Envelope{Epoch: r.host.operatorEpoch, Scope: binding, Payload: state.Stamp}), Revision: state.Revision, Mechanism: wire.PolicyObservationMechanismNative}
			return answer.Next != after, nil
		},
		Recheck: func() error {
			if e := r.host.ctx.Err(); e != nil {
				return e
			}
			_, e := r.authorize()
			return e
		},
		Deadline: func() time.Time { return deadline },
	})
	if err != nil {
		if r.ctx.Err() != nil {
			return wire.PolicyObservation{}, r.ctx.Err()
		}
		return refusal(authorityOutcome(err))
	}
	switch outcome {
	case watch.Answered:
		return answer, nil
	case watch.Unchanged:
		answer.Outcome = wire.PolicyObservationOutcomeUnchanged
		return answer, nil
	default:
		return refusal(wire.PolicyObservationOutcomeUnavailable)
	}
}
