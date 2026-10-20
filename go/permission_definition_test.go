package rights

import (
	"strings"
	"testing"

	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

func testDefinition() wire.PermissionDefinition {
	return wire.PermissionDefinition{Action: "example/use", OwnerContract: "example/owner@1", Operations: []string{"example/owner@1#Use"}, ResourceProfile: LegacyExactResourceProfile, ResourceType: "string", EnforcedBy: []string{"example/owner@1"}, Disclosure: "Apply an existing effect.", Lifecycle: "Exact account-owned resource.", FirstUse: wire.PermissionFirstUseExact, Served: true}
}
func testProfiles() map[string]func(string) bool {
	return map[string]func(string) bool{LegacyExactResourceProfile: func(resource string) bool { return ValidDecisionQuery("example/use", resource) }}
}

func TestDefinitionCatalogRefusesIncompleteAndUnknownBindings(t *testing.T) {
	for name, mutate := range map[string]func(*wire.PermissionDefinition){
		"unknown profile":     func(d *wire.PermissionDefinition) { d.ResourceProfile = "example/profile@1" },
		"unknown version":     func(d *wire.PermissionDefinition) { d.ResourceProfile = "abstraction.credentials/named-use@2" },
		"unknown first use":   func(d *wire.PermissionDefinition) { d.FirstUse = wire.PermissionFirstUse(99) },
		"unserved admission":  func(d *wire.PermissionDefinition) { d.Served = false; d.EnforcedBy = nil },
		"unserved enforcer":   func(d *wire.PermissionDefinition) { d.Served = false; d.FirstUse = wire.PermissionFirstUseNone },
		"missing enforcer":    func(d *wire.PermissionDefinition) { d.EnforcedBy = nil },
		"missing operation":   func(d *wire.PermissionDefinition) { d.Operations = nil },
		"duplicate operation": func(d *wire.PermissionDefinition) { d.Operations = append(d.Operations, d.Operations[0]) },
		"control":             func(d *wire.PermissionDefinition) { d.Disclosure = "effect\n" },
		"oversized":           func(d *wire.PermissionDefinition) { d.Lifecycle = strings.Repeat("x", 2049) },
	} {
		t.Run(name, func(t *testing.T) {
			d := testDefinition()
			mutate(&d)
			if _, err := NewDefinitionCatalog([]wire.PermissionDefinition{d}, testProfiles()); err == nil {
				t.Fatal("invalid definition accepted")
			}
		})
	}
	if _, err := NewDefinitionCatalog([]wire.PermissionDefinition{testDefinition(), testDefinition()}, testProfiles()); err == nil {
		t.Fatal("duplicate action accepted")
	}
}

func TestDefinitionCatalogIsImmutableAndPreservesLegacyExactGrammar(t *testing.T) {
	d := testDefinition()
	c, err := NewDefinitionCatalog([]wire.PermissionDefinition{d}, testProfiles())
	if err != nil {
		t.Fatal(err)
	}
	d.Operations[0] = "changed"
	d.EnforcedBy[0] = "changed"
	read, ok := c.Lookup("example/use")
	if !ok || read.Operations[0] != "example/owner@1#Use" || read.EnforcedBy[0] != "example/owner@1" {
		t.Fatal("constructor retained mutable metadata")
	}
	read.Operations[0] = "changed"
	all := c.Definitions()
	all[0].EnforcedBy[0] = "changed"
	read, _ = c.Lookup("example/use")
	if read.Operations[0] == "changed" || read.EnforcedBy[0] == "changed" {
		t.Fatal("read exposed mutable metadata")
	}
	for _, resource := range []string{"*", "name", strings.Repeat("x", 1024)} {
		if c.FirstUse("example/use", resource) != wire.PermissionFirstUseExact {
			t.Fatalf("legacy exact resource %q changed", resource)
		}
	}
	for _, resource := range []string{"", "bad\n", strings.Repeat("x", 1025)} {
		if c.ValidResource("example/use", resource) {
			t.Fatal("invalid exact grammar accepted")
		}
	}
	if c.FirstUse("example/unknown", "name") != wire.PermissionFirstUseNone {
		t.Fatal("unknown action admitted")
	}
	d = testDefinition()
	d.Served = false
	d.EnforcedBy = nil
	d.FirstUse = wire.PermissionFirstUseNone
	c, err = NewDefinitionCatalog([]wire.PermissionDefinition{d}, testProfiles())
	if err != nil || c.FirstUse("example/use", "name") != wire.PermissionFirstUseNone {
		t.Fatal("unserved definition admitted")
	}
}

func TestDefinitionProfileBindingsAreCompiledAndShared(t *testing.T) {
	for _, profiles := range []map[string]func(string) bool{nil, {LegacyExactResourceProfile: nil}, {"example/profile@01": func(string) bool { return true }}} {
		if _, err := NewDefinitionCatalog([]wire.PermissionDefinition{testDefinition()}, profiles); err == nil {
			t.Fatal("missing or malformed compiled profile accepted")
		}
	}
	profiles := testProfiles()
	first, second := testDefinition(), testDefinition()
	second.Action = "example/other"
	catalogue, err := NewDefinitionCatalog([]wire.PermissionDefinition{first, second}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	profiles[LegacyExactResourceProfile] = func(string) bool { return false }
	if !catalogue.ValidResource(first.Action, "*") || !catalogue.ValidResource(second.Action, "*") {
		t.Fatal("external profile map mutation changed shared binding")
	}
}
