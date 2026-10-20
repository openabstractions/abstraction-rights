package rights

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

const (
	MaxBatchResources        = 256
	MaxTargetBytes           = 16 << 10
	MaxPermissionEffect      = 64
	MaxPermissionDefinitions = 256
	MaxPermissionBundles     = 64
	MaxSelectorFrameBytes    = 1 << 20
)

// ResourceProfile binds one immutable owning IDL profile. Prepare resolves public
// requested targets before policy locks. Validate and Equal are pure: no resource
// lookup, provider lock, policy reentry, Ask or effect callback is allowed.
// Captured receiving evidence is validated, never recaptured, on the quiet path.
type ResourceProfile struct {
	Prepare  func([]byte) ([]byte, error)
	Validate func([]byte) bool
	Equal    func([]byte, []byte) bool
	Describe func([]byte) (string, error)
	// AllowAll is immutable grammar, independent of current receiver availability.
	AllowAll bool
}

var ErrPermissionUnavailable = errors.New("rights: receiving permission unavailable")

// LegacyEquivalence is a trusted compiled block-only link. A fixed Resource
// denotes a coarse overlapping collection. For an exact legacy resource,
// Resource is empty and Concrete derives its owning typed target. Functions
// cannot be installed by an app or descriptor. Changes require new profile
// semantics/version; the stable Mode participates in the definition digest.
type LegacyEquivalence struct {
	Action     string
	Resource   string
	Permission wire.PermissionKey
	Mode       string
	Concrete   func(string) ([]byte, bool)
}

type selectorCatalog struct {
	definitions map[wire.PermissionKey]wire.SelectorPermissionDefinition
	profiles    map[string]ResourceProfile
	bundles     map[string]wire.PermissionBundleDefinition
	equivalents []LegacyEquivalence
	digest      string
}

func keyOf(d wire.PermissionDefinition) wire.PermissionKey {
	return wire.PermissionKey{Action: d.Action, ResourceProfile: d.ResourceProfile}
}
func permissionKeyString(k wire.PermissionKey) string { return k.Action + "\x00" + k.ResourceProfile }
func validPermissionKey(k wire.PermissionKey) bool {
	return ValidActionName(k.Action) && definitionProfile(k.ResourceProfile)
}
func cloneSelection(s wire.PermissionSelection) wire.PermissionSelection {
	s.Selector.Target = slices.Clone(s.Selector.Target)
	return s
}
func cloneSelections(ss []wire.PermissionSelection) []wire.PermissionSelection {
	out := make([]wire.PermissionSelection, len(ss))
	for i, s := range ss {
		out[i] = cloneSelection(s)
	}
	return out
}
func cloneExpansion(x wire.BundleExpansion) wire.BundleExpansion {
	x.Selector.Target = slices.Clone(x.Selector.Target)
	x.Selections = cloneSelections(x.Selections)
	return x
}
func cloneSelectorDefinition(d wire.SelectorPermissionDefinition) wire.SelectorPermissionDefinition {
	d.Definition = cloneDefinition(d.Definition)
	d.SupportedSelectors = slices.Clone(d.SupportedSelectors)
	d.FirstUseSelectors = slices.Clone(d.FirstUseSelectors)
	return d
}
func cloneBundle(d wire.PermissionBundleDefinition) wire.PermissionBundleDefinition {
	d.SupportedSelectors = slices.Clone(d.SupportedSelectors)
	d.Members = slices.Clone(d.Members)
	return d
}
func validKinds(ks []wire.ResourceSelectorKind, empty bool) bool {
	if len(ks) > 2 || !empty && len(ks) == 0 {
		return false
	}
	for i, k := range ks {
		if k != wire.ResourceSelectorKindOne && k != wire.ResourceSelectorKindAll || i > 0 && ks[i-1] >= k {
			return false
		}
	}
	return true
}

// WithSelectors builds one immutable catalogue with explicit legacy routes and
// full-key typed rows. The receiver composes it once before sharing a policy.
// Existing action-only Lookup/FirstUse remain their original legacy projection.
func (c *DefinitionCatalog) WithSelectors(defs []wire.SelectorPermissionDefinition, profiles map[string]ResourceProfile, bundles []wire.PermissionBundleDefinition, equivalents []LegacyEquivalence) (*DefinitionCatalog, error) {
	if c == nil || len(c.definitions)+len(defs) > MaxPermissionDefinitions || len(bundles) > MaxPermissionBundles {
		return nil, errors.New("rights: selector catalogue bound")
	}
	out := &DefinitionCatalog{definitions: map[string]wire.PermissionDefinition{}, profiles: map[string]func(string) bool{}}
	for a, d := range c.definitions {
		out.definitions[a] = cloneDefinition(d)
	}
	for p, v := range c.profiles {
		out.profiles[p] = v
	}
	sc := &selectorCatalog{definitions: map[wire.PermissionKey]wire.SelectorPermissionDefinition{}, profiles: map[string]ResourceProfile{}, bundles: map[string]wire.PermissionBundleDefinition{}}
	for _, d := range c.Definitions() {
		sc.definitions[keyOf(d)] = wire.SelectorPermissionDefinition{Definition: d, Label: d.Action, SupportedSelectors: []wire.ResourceSelectorKind{}, FirstUseSelectors: []wire.ResourceSelectorKind{}, Collection: d.Lifecycle, AllEffect: "", RequestType: d.ResourceType}
	}
	for p, b := range profiles {
		if !definitionProfile(p) || b.Prepare == nil || b.Validate == nil || b.Equal == nil {
			return nil, errors.New("rights: invalid typed profile binding")
		}
		sc.profiles[p] = b
	}
	for _, d := range defs {
		k := keyOf(d.Definition)
		if !validPermissionKey(k) || sc.profiles[k.ResourceProfile].Validate == nil || !definitionText(d.Label, 128) || !definitionText(d.RequestType, 128) || !definitionText(d.Collection, 2048) || !validKinds(d.SupportedSelectors, !d.Definition.Served) || !validKinds(d.FirstUseSelectors, true) || !definitionText(d.Definition.OwnerContract, 128) || !definitionTexts(d.Definition.Operations, 256) || !definitionText(d.Definition.ResourceType, 128) || !definitionText(d.Definition.Disclosure, 2048) || !definitionText(d.Definition.Lifecycle, 2048) {
			return nil, errors.New("rights: invalid selector definition")
		}
		if _, dup := sc.definitions[k]; dup {
			return nil, errors.New("rights: duplicate action/profile definition")
		}
		if d.Definition.Served && !definitionTexts(d.Definition.EnforcedBy, 128) || !d.Definition.Served && (len(d.Definition.EnforcedBy) != 0 || len(d.FirstUseSelectors) != 0 || len(d.SupportedSelectors) != 0) {
			return nil, errors.New("rights: invalid served selectors")
		}
		if slices.Contains(d.SupportedSelectors, wire.ResourceSelectorKindAll) && !definitionText(d.AllEffect, 2048) || !slices.Contains(d.SupportedSelectors, wire.ResourceSelectorKindAll) && d.AllEffect != "" {
			return nil, errors.New("rights: invalid all effect")
		}
		for _, k := range d.FirstUseSelectors {
			if !slices.Contains(d.SupportedSelectors, k) {
				return nil, errors.New("rights: unsupported first use selector")
			}
		}
		sc.definitions[k] = cloneSelectorDefinition(d)
	}
	out.selectors = sc
	for _, b := range bundles {
		if !definitionProfile(b.BundleRef) || !definitionText(b.OwnerContract, 128) || !definitionText(b.Label, 128) || !definitionText(b.TargetType, 128) || !definitionText(b.Disclosure, 2048) || !validKinds(b.SupportedSelectors, false) || len(b.Members) == 0 || len(b.Members) > MaxPermissionEffect {
			return nil, errors.New("rights: invalid bundle")
		}
		if _, exists := sc.bundles[b.BundleRef]; exists {
			return nil, errors.New("rights: duplicate bundle")
		}
		collection := ""
		for i, k := range b.Members {
			d, ok := sc.definitions[k]
			if !ok || d.Definition.ResourceType != b.TargetType {
				return nil, errors.New("rights: unserved/incompatible bundle member")
			}
			if i > 0 && permissionKeyString(b.Members[i-1]) >= permissionKeyString(k) {
				return nil, errors.New("rights: unsorted/duplicate bundle member")
			}
			if i == 0 {
				collection = d.Collection
			}
			if d.Collection != collection {
				return nil, errors.New("rights: mismatched bundle collection")
			}
			for _, s := range b.SupportedSelectors {
				if s == wire.ResourceSelectorKindAll && !sc.profiles[k.ResourceProfile].AllowAll || s != wire.ResourceSelectorKindOne && s != wire.ResourceSelectorKindAll {
					return nil, errors.New("rights: unsupported bundle selector")
				}
			}
		}
		b.DefinitionDigest = ""
		raw, _ := json.Marshal(b)
		sum := sha256.Sum256(raw)
		b.DefinitionDigest = "sha256:" + hex.EncodeToString(sum[:])
		sc.bundles[b.BundleRef] = cloneBundle(b)
	}
	for _, e := range equivalents {
		if !ValidActionName(e.Action) || !definitionText(e.Mode, 128) || !validPermissionKey(e.Permission) || e.Resource != "" && !boundedDecisionString(e.Resource, 1024) || e.Resource == "" && e.Concrete == nil {
			return nil, errors.New("rights: invalid legacy equivalence")
		}
		if _, ok := sc.definitions[e.Permission]; !ok {
			return nil, errors.New("rights: unknown equivalent permission")
		}
		sc.equivalents = append(sc.equivalents, e)
	}
	slices.SortFunc(sc.equivalents, func(a, b LegacyEquivalence) int {
		return strings.Compare(a.Action+"\x00"+a.Resource+"\x00"+permissionKeyString(a.Permission)+"\x00"+a.Mode, b.Action+"\x00"+b.Resource+"\x00"+permissionKeyString(b.Permission)+"\x00"+b.Mode)
	})
	type link struct {
		Action, Resource, Mode string
		Permission             wire.PermissionKey
	}
	links := make([]link, 0, len(sc.equivalents))
	for _, e := range sc.equivalents {
		links = append(links, link{e.Action, e.Resource, e.Mode, e.Permission})
	}
	digestData, _ := json.Marshal(struct {
		Definitions []wire.SelectorPermissionDefinition
		Bundles     []wire.PermissionBundleDefinition
		Links       []link
	}{out.SelectorDefinitions(), out.PermissionBundles(), links})
	sum := sha256.Sum256(digestData)
	sc.digest = "sha256:" + hex.EncodeToString(sum[:])
	return out, nil
}

func (c *DefinitionCatalog) SelectorDefinitions() []wire.SelectorPermissionDefinition {
	if c == nil || c.selectors == nil {
		return nil
	}
	out := make([]wire.SelectorPermissionDefinition, 0, len(c.selectors.definitions))
	for _, d := range c.selectors.definitions {
		out = append(out, cloneSelectorDefinition(d))
	}
	slices.SortFunc(out, func(a, b wire.SelectorPermissionDefinition) int {
		return strings.Compare(permissionKeyString(keyOf(a.Definition)), permissionKeyString(keyOf(b.Definition)))
	})
	return out
}
func (c *DefinitionCatalog) SelectorDefinition(k wire.PermissionKey) (wire.SelectorPermissionDefinition, bool) {
	if c == nil || c.selectors == nil {
		return wire.SelectorPermissionDefinition{}, false
	}
	d, ok := c.selectors.definitions[k]
	return cloneSelectorDefinition(d), ok
}
func (c *DefinitionCatalog) PermissionBundles() []wire.PermissionBundleDefinition {
	if c == nil || c.selectors == nil {
		return nil
	}
	out := make([]wire.PermissionBundleDefinition, 0, len(c.selectors.bundles))
	for _, b := range c.selectors.bundles {
		copy := cloneBundle(b)
		copy.SupportedSelectors = slices.DeleteFunc(copy.SupportedSelectors, func(kind wire.ResourceSelectorKind) bool {
			for _, k := range b.Members {
				d, ok := c.SelectorDefinition(k)
				if !ok || !d.Definition.Served || !slices.Contains(d.SupportedSelectors, kind) {
					return true
				}
			}
			return false
		})
		out = append(out, copy)
	}
	slices.SortFunc(out, func(a, b wire.PermissionBundleDefinition) int { return strings.Compare(a.BundleRef, b.BundleRef) })
	return out
}
func (c *DefinitionCatalog) DefinitionDigest() string {
	if c == nil || c.selectors == nil {
		return ""
	}
	return c.selectors.digest
}
func (c *DefinitionCatalog) ValidSelection(s wire.PermissionSelection) bool {
	d, ok := c.SelectorDefinition(s.Permission)
	if !ok || !d.Definition.Served || !slices.Contains(d.SupportedSelectors, s.Selector.Kind) {
		return false
	}
	return c.ValidStoredSelection(s)
}

// ValidStoredSelection retains immutable known grammar while a receiver is
// unavailable. Stored rules remain readable/removable without granting effects.
func (c *DefinitionCatalog) ValidStoredSelection(s wire.PermissionSelection) bool {
	if c == nil || c.selectors == nil {
		return false
	}
	if _, ok := c.selectors.definitions[s.Permission]; !ok {
		return false
	}
	profile, ok := c.selectors.profiles[s.Permission.ResourceProfile]
	if !ok {
		return false
	}
	if s.Selector.Kind == wire.ResourceSelectorKindAll {
		return s.Selector.Target == nil && profile.AllowAll
	}
	return s.Selector.Kind == wire.ResourceSelectorKindOne && len(s.Selector.Target) > 0 && len(s.Selector.Target) <= MaxTargetBytes && c.selectors.profiles[s.Permission.ResourceProfile].Validate(s.Selector.Target)
}
func (c *DefinitionCatalog) PrepareSelection(s wire.PermissionSelection) (wire.PermissionSelection, error) {
	d, ok := c.SelectorDefinition(s.Permission)
	if !ok {
		return wire.PermissionSelection{}, errors.New("rights: unsupported selection")
	}
	if !d.Definition.Served || !slices.Contains(d.SupportedSelectors, s.Selector.Kind) {
		return wire.PermissionSelection{}, ErrPermissionUnavailable
	}
	s = cloneSelection(s)
	if s.Selector.Kind == wire.ResourceSelectorKindOne {
		if len(s.Selector.Target) == 0 || len(s.Selector.Target) > MaxTargetBytes {
			return wire.PermissionSelection{}, errors.New("rights: invalid target bound")
		}
		target, e := c.selectors.profiles[s.Permission.ResourceProfile].Prepare(s.Selector.Target)
		if e != nil {
			return wire.PermissionSelection{}, e
		}
		s.Selector.Target = target
	}
	if !c.ValidSelection(s) {
		return wire.PermissionSelection{}, errors.New("rights: invalid canonical selection")
	}
	return s, nil
}
func (c *DefinitionCatalog) ValidConcrete(r wire.ConcreteResource) bool {
	return c.ValidSelection(wire.PermissionSelection{Permission: r.Permission, Selector: wire.ResourceSelector{Kind: wire.ResourceSelectorKindOne, Target: r.Target}})
}
func (c *DefinitionCatalog) sameTarget(k wire.PermissionKey, a, b []byte) bool {
	return c != nil && c.selectors != nil && c.selectors.profiles[k.ResourceProfile].Equal != nil && c.selectors.profiles[k.ResourceProfile].Equal(a, b)
}
func (c *DefinitionCatalog) PrepareBundle(ref string, s wire.ResourceSelector) (wire.BundleExpansion, error) {
	if c == nil || c.selectors == nil {
		return wire.BundleExpansion{}, errors.New("rights: selector catalogue unavailable")
	}
	b, ok := c.selectors.bundles[ref]
	if !ok || !slices.Contains(b.SupportedSelectors, s.Kind) {
		return wire.BundleExpansion{}, errors.New("rights: unsupported bundle")
	}
	x := wire.BundleExpansion{BundleRef: ref, DefinitionDigest: b.DefinitionDigest, Selector: s, Selections: make([]wire.PermissionSelection, 0, len(b.Members))}
	for _, k := range b.Members {
		v, e := c.PrepareSelection(wire.PermissionSelection{Permission: k, Selector: s})
		if e != nil {
			return wire.BundleExpansion{}, e
		}
		if len(x.Selections) > 0 && !bytes.Equal(v.Selector.Target, x.Selector.Target) {
			return wire.BundleExpansion{}, errors.New("rights: bundle canonical targets differ")
		}
		x.Selector = v.Selector
		x.Selections = append(x.Selections, v)
	}
	return cloneExpansion(x), nil
}
func (c *DefinitionCatalog) ValidateExpansion(x wire.BundleExpansion) bool {
	if c == nil || c.selectors == nil || len(x.Selections) == 0 || len(x.Selections) > MaxPermissionEffect || !definitionProfile(x.BundleRef) || !boundedDecisionString(x.DefinitionDigest, 128) {
		return false
	}
	for i, s := range x.Selections {
		if !c.ValidStoredSelection(s) || s.Selector.Kind != x.Selector.Kind || !bytes.Equal(s.Selector.Target, x.Selector.Target) || i > 0 && permissionKeyString(x.Selections[i-1].Permission) >= permissionKeyString(s.Permission) {
			return false
		}
	}
	return true
}

// PreparePermissionEffect resolves a trusted complete proposal before Book or
// policy locks. A caller chooses explicit selections or one immutable bundle.
func (c *DefinitionCatalog) PreparePermissionEffect(subject wire.Subject, selections []wire.PermissionSelection, bundleRef string, selector *wire.ResourceSelector) (wire.PermissionEffect, error) {
	s, e := writableSubject(subject)
	if e != nil {
		return wire.PermissionEffect{}, e
	}
	out := wire.PermissionEffect{Subject: s, Selections: []wire.PermissionSelection{}}
	if bundleRef != "" {
		if len(selections) != 0 || selector == nil {
			return out, errors.New("rights: conflicting effect forms")
		}
		x, e := c.PrepareBundle(bundleRef, *selector)
		if e != nil {
			return out, e
		}
		out.Bundle = &x
		out.Selections = cloneSelections(x.Selections)
	} else {
		if selector != nil || len(selections) == 0 || len(selections) > MaxPermissionEffect {
			return out, errors.New("rights: effect bound")
		}
		for _, v := range selections {
			v, e = c.PrepareSelection(v)
			if e != nil {
				return out, e
			}
			out.Selections = append(out.Selections, v)
		}
		slices.SortFunc(out.Selections, func(a, b wire.PermissionSelection) int {
			return strings.Compare(permissionKeyString(a.Permission), permissionKeyString(b.Permission))
		})
	}
	if !c.ValidPermissionEffect(out) {
		return wire.PermissionEffect{}, errors.New("rights: invalid effect")
	}
	return out, nil
}
func (c *DefinitionCatalog) ValidPermissionEffect(effect wire.PermissionEffect) bool {
	if !c.ValidStoredPermissionEffect(effect) {
		return false
	}
	for _, s := range effect.Selections {
		if !c.ValidSelection(s) {
			return false
		}
	}
	return true
}
func (c *DefinitionCatalog) ValidStoredPermissionEffect(effect wire.PermissionEffect) bool {
	if !validStoredSubject(effect.Subject) || len(effect.Selections) == 0 || len(effect.Selections) > MaxPermissionEffect {
		return false
	}
	for i, s := range effect.Selections {
		if !c.ValidStoredSelection(s) || i > 0 && permissionKeyString(effect.Selections[i-1].Permission) >= permissionKeyString(s.Permission) {
			return false
		}
	}
	if effect.Bundle != nil {
		x := effect.Bundle
		if !c.ValidateExpansion(*x) || c.selectors == nil {
			return false
		}
		b, ok := c.selectors.bundles[x.BundleRef]
		if !ok || b.DefinitionDigest != x.DefinitionDigest || len(b.Members) != len(x.Selections) || len(effect.Selections) != len(x.Selections) {
			return false
		}
		for i, s := range x.Selections {
			if b.Members[i] != s.Permission || permissionKeyString(effect.Selections[i].Permission) != permissionKeyString(s.Permission) || effect.Selections[i].Selector.Kind != s.Selector.Kind || !bytes.Equal(effect.Selections[i].Selector.Target, s.Selector.Target) {
				return false
			}
		}
	}
	return true
}

func (c *DefinitionCatalog) DescribeSelection(selection wire.PermissionSelection) (string, error) {
	if !c.ValidSelection(selection) {
		return "", errors.New("rights: invalid target explanation")
	}
	d, _ := c.SelectorDefinition(selection.Permission)
	if selection.Selector.Kind == wire.ResourceSelectorKindAll {
		return d.AllEffect, nil
	}
	describe := c.selectors.profiles[selection.Permission.ResourceProfile].Describe
	if describe == nil {
		return "", errors.New("rights: owning target explanation unavailable")
	}
	label, e := describe(selection.Selector.Target)
	if e != nil || !definitionText(label, 4096) {
		return "", errors.New("rights: invalid owning target explanation")
	}
	return label, nil
}
func (c *DefinitionCatalog) PermissionBundle(ref string) (wire.PermissionBundleDefinition, bool) {
	if c == nil || c.selectors == nil {
		return wire.PermissionBundleDefinition{}, false
	}
	b, ok := c.selectors.bundles[ref]
	return cloneBundle(b), ok
}
func (c *DefinitionCatalog) HasSelectors() bool { return c != nil && c.selectors != nil }
