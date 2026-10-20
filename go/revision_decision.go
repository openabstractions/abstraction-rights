package rights

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"math"
	"strconv"
	"strings"
)

const orderedDecisionProfile = "rights-decisions@8"

type decisionOrder struct {
	Epoch    string `json:"epoch"`
	Sequence int64  `json:"sequence"`
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validDecisionOrder(o *decisionOrder) bool {
	return o != nil && lowerHex(o.Epoch, 32) && o.Sequence >= 0
}
func revisionContent(f decisionFile) decisionFile {
	if f.Order != nil {
		f.Profile = DecisionProfile
		f.Order = nil
	}
	return f
}
func (p *DecisionPolicy) configuration(label string) string {
	data, _ := json.Marshal(struct {
		Label                                          string
		Seed                                           []string
		Definitions, Defaults, Account, DefaultAccount string
	}{label, p.seed, p.Definitions.DefinitionDigest(), p.defaultsDigest(), p.native.Account, p.defaultAccount})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// EnableRevisionDecisions initializes the existing CAS file's durable order.
// Call after configuration and before sharing. The bounded native label versions
// the owner's callback semantics; bump it when those semantics change. Configure
// no policy fields afterwards. The library hashes this label with actual config.
// Profile7 content hashes survive metadata migration; legacy2..6 canonicalize once.
func (p *DecisionPolicy) EnableRevisionDecisions(label string) error {
	if len(label) == 0 || len(label) > 128 {
		return errors.New("rights: invalid revision configuration label")
	}
	for _, c := range label {
		if c < 0x20 || c > 0x7e {
			return errors.New("rights: invalid revision configuration label")
		}
	}
	config := p.configuration(label)
	if p.revisionConfiguration != "" {
		if p.revisionConfiguration == label && p.revisionConfigurationDigest == config {
			return nil
		}
		return errors.New("rights: revision configuration frozen")
	}
	if err := p.regular(); err != nil {
		return err
	}
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return err
	}
	err := p.change(func(data []byte) ([]byte, error) {
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		if f.Order != nil {
			return data, nil
		}
		f.Profile = orderedDecisionProfile
		f.Order = &decisionOrder{Epoch: hex.EncodeToString(epoch[:])}
		return json.Marshal(f)
	})
	if err != nil {
		return err
	}
	p.revisionConfiguration = label
	p.revisionConfigurationDigest = config
	p.decoded.reset()
	return nil
}

// orderChange runs inside the existing CAS edit. Every writer preserves order,
// including a policy object that has not enabled the new receiving method.
func (p *DecisionPolicy) orderChange(data, next []byte) ([]byte, error) {
	if bytes.Equal(data, next) {
		return next, nil
	}
	old, err := p.decodeDecision(data)
	if err != nil {
		return nil, err
	}
	if old.Order == nil {
		return next, nil
	}
	var f decisionFile
	if err = json.Unmarshal(next, &f); err != nil {
		return nil, err
	}
	// Existing writers set Profile7; restore the private metadata here.
	a, _ := json.Marshal(revisionContent(old))
	b, _ := json.Marshal(revisionContent(f))
	if bytes.Equal(a, b) {
		return data, nil
	}
	if old.Order.Sequence == math.MaxInt64 {
		return nil, errors.New("rights: decision order exhausted")
	}
	f.Profile = orderedDecisionProfile
	f.Order = &decisionOrder{Epoch: old.Order.Epoch, Sequence: old.Order.Sequence + 1}
	return json.Marshal(f)
}

func revisionObservation(o *decisionOrder, config string) string {
	return "rf1." + o.Epoch + "." + config + "." + strconv.FormatInt(o.Sequence, 10)
}
func parseRevisionObservation(s string) (epoch, config string, sequence int64, ok bool) {
	if len(s) > 128 {
		return
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 || parts[0] != "rf1" || !lowerHex(parts[1], 32) || !lowerHex(parts[2], 64) {
		return
	}
	n, e := strconv.ParseInt(parts[3], 10, 64)
	if e != nil || n < 0 || strconv.FormatInt(n, 10) != parts[3] {
		return
	}
	return parts[1], parts[2], n, true
}

// DecideForAtLeastRevisionContext evaluates the fence and decision from one read.
// A minimum is an observation requirement, never a permission or a lease.
func (p *DecisionPolicy) DecideForAtLeastRevisionContext(ctx context.Context, subject wire.Subject, action, resource, minimum string) wire.RevisionDecision {
	return p.CheckLegacyOperationAtLeastRevisionContext(ctx, subject, wire.LegacyOperationRequest{LegacyAction: action, LegacyResource: resource}, minimum)
}

// CheckLegacyOperationAtLeastRevisionContext evaluates the complete operation
// and its minimum observation from one policy read and one clock sample.
func (p *DecisionPolicy) CheckLegacyOperationAtLeastRevisionContext(ctx context.Context, subject wire.Subject, req wire.LegacyOperationRequest, minimum string) wire.RevisionDecision {
	refusal := func(out wire.DecisionOutcome) wire.RevisionDecision {
		return wire.RevisionDecision{Decision: wire.Decision{Outcome: out}}
	}
	if ctx.Err() != nil {
		return refusal(wire.DecisionOutcomeUnavailable)
	}
	s, err := NormalizeDecisionSubject(subject)
	if err != nil || !p.legacyOperationValid(req, remoteSubject(s)) {
		return refusal(wire.DecisionOutcomeInvalid)
	}
	if minimum != "" {
		if _, _, _, ok := parseRevisionObservation(minimum); !ok {
			return refusal(wire.DecisionOutcomeInvalid)
		}
	}
	if p.revisionConfiguration == "" || p.configuration(p.revisionConfiguration) != p.revisionConfigurationDigest {
		p.logUnavailable("config", errors.New("policy revision configuration unavailable"))
		return refusal(wire.DecisionOutcomeUnavailable)
	}
	ctx, preparationErr := p.prepareMetaOperation(ctx, req.LegacyAction, req.LegacyResource)
	if p.preparationStopsRead(ctx, preparationErr) {
		return refusal(wire.DecisionOutcomeUnavailable)
	}
	f, revision, err := p.readDecisionContext(ctx)
	if err != nil || f.Order == nil {
		return refusal(wire.DecisionOutcomeUnavailable)
	}
	config := p.revisionConfigurationDigest
	if minimum != "" {
		epoch, c, n, _ := parseRevisionObservation(minimum)
		if epoch != f.Order.Epoch || c != config || n > f.Order.Sequence {
			return refusal(wire.DecisionOutcomeUnavailable)
		}
	}
	d := p.afterMetaPreparation(p.legacyOperationExplained(ctx, f, revision, s, req, p.now()), preparationErr).decision()
	if d.PolicyRevision == "" {
		return wire.RevisionDecision{Decision: d}
	}
	return wire.RevisionDecision{Decision: d, ObservedRevision: revisionObservation(f.Order, config)}
}
