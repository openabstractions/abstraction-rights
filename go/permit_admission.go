package rights

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// ConfigurePermitAdmission configures one native provider's permit boundary
// before sharing the policy. Preparation reuses the host's outer immutable-fact
// refresh. The callback captures those facts without native/Book/directory calls;
// its returned guard must be a quiet current read safe under the policy CAS.
// Revocation and other actions retain their existing behavior.
func (p *DecisionPolicy) ConfigurePermitAdmission(action string, prepare func(context.Context, wire.Subject, wire.PermissionSelection) (func() error, error)) error {
	if !ValidActionName(action) || prepare == nil || p.permitAdmission != nil {
		return errors.New("rights: invalid permit admission configuration")
	}
	p.permitAdmissionAction, p.permitAdmission = action, prepare
	return nil
}

func (p *DecisionPolicy) preparePermit(ctx context.Context, subject wire.Subject, selection wire.PermissionSelection, permit *bool) (func() error, error) {
	if permit == nil || !*permit || p.permitAdmission == nil || selection.Permission.Action != p.permitAdmissionAction {
		return func() error { return nil }, nil
	}
	ctx, err := p.prepareMetaOperation(ctx, MetaAnswerAction, MetaScopeApps)
	if err != nil {
		return nil, err
	}
	guard, err := p.permitAdmission(ctx, subject, selection)
	if err != nil {
		return nil, err
	}
	if guard == nil {
		return nil, errors.New("rights: permit admission unavailable")
	}
	return guard, nil
}

func (p *DecisionPolicy) prepareLegacyPermit(ctx context.Context, subject wire.Subject, action, resource string, permit *bool) (func() error, error) {
	target, _ := json.Marshal(resource)
	return p.preparePermit(ctx, subject, wire.PermissionSelection{Permission: wire.PermissionKey{Action: action, ResourceProfile: LegacyExactResourceProfile}, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: target}}, permit)
}

// InvalidateProviderPermitsContext retires only exact permits for the configured
// native provider. The provider freezes target admission before calling it and
// retains that reservation until its own lifecycle publication finishes.
func (p *DecisionPolicy) InvalidateProviderPermitsContext(ctx context.Context, resource string) error {
	if p.permitAdmission == nil || !ValidDecisionQuery(p.permitAdmissionAction, resource) {
		return errors.New("rights: provider invalidation unavailable")
	}
	if err := p.regular(); err != nil {
		return err
	}
	noWrite := errors.New("rights: no provider permits to invalidate")
	err := p.changeContext(ctx, func(data []byte) ([]byte, error) {
		f, err := p.decodeDecision(data)
		if err != nil {
			return nil, err
		}
		before, selectorsBefore := len(f.Rules), len(f.SelectorRules)
		f.Rules = slices.DeleteFunc(f.Rules, func(rule decisionRule) bool {
			return rule.Permit && rule.Action == p.permitAdmissionAction && rule.Resource == resource
		})
		f.SelectorRules = slices.DeleteFunc(f.SelectorRules, func(rule selectorRule) bool {
			var target string
			return rule.Permit && rule.Selection.Permission.Action == p.permitAdmissionAction && rule.Selection.Permission.ResourceProfile == LegacyExactResourceProfile && rule.Selection.Selector.Kind == wire.ResourceSelectorKindOne && json.Unmarshal(rule.Selection.Selector.Target, &target) == nil && target == resource
		})
		if len(f.Rules) == before && len(f.SelectorRules) == selectorsBefore {
			return nil, noWrite
		}
		if len(f.Rules) == 0 {
			f.Rules = nil
		}
		if len(f.SelectorRules) == 0 {
			f.SelectorRules = nil
		}
		pruneOrigins(&f)
		f.Profile = DecisionProfile
		return json.Marshal(f)
	})
	if errors.Is(err, noWrite) {
		return nil
	}
	return err
}
