package rights

import (
	"context"
	"slices"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// ApplyRemotePairingAllowContext is trusted native runtime composition, with
// no public service route. The caller must pin the actual native Asks occurrence
// while calling it. authorize must recheck the native operator, Book approval,
// current peer/offer/transcript and complete receiver-canonical legacy effect
// on every invocation, including CAS retries. Rule and actor data confer no
// authority. The runtime preparer owns eligible actions and resource meaning;
// this owner validates registered exact non-meta rules, not typed selectors.
//
// One remote subject in the native actor's receiving account gains all members
// and durable completion in one conditional replacement. Existing live Blocks
// refuse the complete effect; other setters' live permits are preserved. This
// reuses the existing permanent first-use lifetime. Completed occurrences never
// restore revoked rights. No-grant pairing must make no call. This entry starts
// no listener and establishes no pairing, peer admission or bilateral commit.
func (p *DecisionPolicy) ApplyRemotePairingAllowContext(ctx context.Context, expected string, rules []wire.PolicyRule, edit RuleEdit, id string, retained []string, authorize func() error) (wire.PolicyEdit, error) {
	receipt, ok := firstUseAllowReceipt(id, retained)
	if !ok || edit.Permit == nil || !*edit.Permit || edit.TTL != 0 || !edit.Deadline.IsZero() {
		return wire.PolicyEdit{Outcome: wire.PolicyEditOutcomeInvalid}, nil
	}
	permit := true
	edit.Permit = &permit
	edit.Exact = true
	edit.PreserveOtherSetter = true
	edit.QuestionID = id
	return p.changeRulesForPairing(ctx, expected, slices.Clone(rules), edit, authorize, receipt, true)
}
