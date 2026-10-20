package rights

import (
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const LegacyExactResourceProfile = "abstraction.rights/legacy-exact-string@1"

// DefinitionCatalog binds immutable metadata to trusted compiled resource
// profiles. Each configured profile has one owning validator for every action.
// Capability owners supply their profile identity and validator at composition.
type DefinitionCatalog struct {
	definitions map[string]wire.PermissionDefinition
	profiles    map[string]func(string) bool
	selectors   *selectorCatalog
}

func definitionText(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}
func definitionTexts(values []string, max int) bool {
	if len(values) == 0 || len(values) > 64 {
		return false
	}
	seen := make(map[string]bool)
	for _, value := range values {
		if !definitionText(value, max) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func definitionProfile(value string) bool {
	name, version, ok := strings.Cut(value, "@")
	n, err := strconv.ParseUint(version, 10, 32)
	return ok && definitionText(value, 128) && ValidActionName(name) && err == nil && n > 0 && strconv.FormatUint(n, 10) == version
}
func cloneDefinition(value wire.PermissionDefinition) wire.PermissionDefinition {
	value.Operations = slices.Clone(value.Operations)
	value.EnforcedBy = slices.Clone(value.EnforcedBy)
	return value
}

// NewDefinitionCatalog receives the profile bindings known to trusted composition.
// Unknown referenced profiles/versions and incomplete bindings refuse the whole
// catalogue. Binding serialization or app metadata creates no profile authority.
func NewDefinitionCatalog(definitions []wire.PermissionDefinition, profiles map[string]func(string) bool) (*DefinitionCatalog, error) {
	catalog := &DefinitionCatalog{definitions: make(map[string]wire.PermissionDefinition), profiles: make(map[string]func(string) bool)}
	for name, validate := range profiles {
		if !definitionProfile(name) || validate == nil {
			return nil, errors.New("rights: invalid compiled resource profile")
		}
		catalog.profiles[name] = validate
	}
	for _, m := range definitions {
		knownFirstUse := m.FirstUse == wire.PermissionFirstUseNone || m.FirstUse == wire.PermissionFirstUseExact || m.FirstUse == wire.PermissionFirstUseConsumingPaired
		if !ValidActionName(m.Action) || !definitionText(m.OwnerContract, 128) || !definitionTexts(m.Operations, 256) ||
			catalog.profiles[m.ResourceProfile] == nil || !knownFirstUse || !definitionText(m.ResourceType, 128) || !definitionText(m.Disclosure, 2048) ||
			!definitionText(m.Lifecycle, 2048) || (m.Served && !definitionTexts(m.EnforcedBy, 128)) ||
			(!m.Served && (len(m.EnforcedBy) != 0 || m.FirstUse != wire.PermissionFirstUseNone)) {
			return nil, errors.New("rights: invalid compiled permission definition")
		}
		if _, duplicate := catalog.definitions[m.Action]; duplicate {
			return nil, errors.New("rights: duplicate permission definition")
		}
		catalog.definitions[m.Action] = cloneDefinition(m)
	}
	return catalog, nil
}
func (c *DefinitionCatalog) Lookup(action string) (wire.PermissionDefinition, bool) {
	if c == nil {
		return wire.PermissionDefinition{}, false
	}
	definition, ok := c.definitions[action]
	return cloneDefinition(definition), ok
}
func (c *DefinitionCatalog) Definitions() []wire.PermissionDefinition {
	if c == nil {
		return nil
	}
	var result []wire.PermissionDefinition
	for _, definition := range c.definitions {
		result = append(result, cloneDefinition(definition))
	}
	slices.SortFunc(result, func(a, b wire.PermissionDefinition) int { return strings.Compare(a.Action, b.Action) })
	return result
}
func (c *DefinitionCatalog) ValidResource(action, resource string) bool {
	if c == nil || !ValidDecisionQuery(action, resource) {
		return false
	}
	definition, ok := c.definitions[action]
	return ok && c.profiles[definition.ResourceProfile](resource)
}

// FirstUse reports served, resource-valid admission. Consuming paired requests
// retain their consuming operation's existing closed profile restrictions.
func (c *DefinitionCatalog) FirstUse(action, resource string) wire.PermissionFirstUse {
	if !c.ValidResource(action, resource) {
		return wire.PermissionFirstUseNone
	}
	definition := c.definitions[action]
	if !definition.Served {
		return wire.PermissionFirstUseNone
	}
	return definition.FirstUse
}
