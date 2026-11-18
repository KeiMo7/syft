package diff

import "github.com/anchore/syft/syft/pkg"

// ChangeType is the kind of difference detected for a single component identity.
type ChangeType string

const (
	// Added components exist only in the new SBOM.
	Added ChangeType = "added"

	// Removed components exist only in the old SBOM.
	Removed ChangeType = "removed"

	// VersionChanged components exist in both SBOMs but report different versions.
	VersionChanged ChangeType = "version-changed"

	// VersionUnknown components are matched in both SBOMs but at least one side has no
	// usable version, so an upgrade/downgrade decision cannot be made. They are never
	// reported as "no change".
	VersionUnknown ChangeType = "version-unknown"
)

// VersionChangeDirection refines a VersionChanged result based on semantic version comparison.
type VersionChangeDirection string

const (
	// NoDirection means the versions could not be compared as semantic versions.
	NoDirection VersionChangeDirection = "uncomparable"

	// Upgrade means the new version is semantically higher than the old one.
	Upgrade VersionChangeDirection = "upgrade"

	// Downgrade means the new version is semantically lower than the old one.
	Downgrade VersionChangeDirection = "downgrade"

	// RevisionOnly means major and minor are unchanged and only the patch (revision)
	// number differs; it is only used when the new version is newer.
	RevisionOnly VersionChangeDirection = "revision-only"
)

// Layer describes where a component sits in the dependency graph.
type Layer string

const (
	// DirectDependency is a package that is depended on by nothing (a root dependency).
	DirectDependency Layer = "direct"

	// TransitiveDependency is a package that at least one other package depends on.
	TransitiveDependency Layer = "transitive"

	// UnknownLayer is used when the SBOM carries no dependency relationships at all, so
	// the position of a component in the dependency graph cannot be determined.
	UnknownLayer Layer = "unknown"
)

// IdentityRule records which deterministic rule was used to match a component.
type IdentityRule string

const (
	// PURLIdentity matches on a normalized Package URL with the version stripped.
	PURLIdentity IdentityRule = "purl"

	// NameTypeIdentity is the degraded fallback: same package type and name, compared
	// together with the version. Matches made with this rule are flagged unreliable.
	NameTypeIdentity IdentityRule = "name+type"

	// NameIdentity is a further degraded fallback used when a package has no type either.
	NameIdentity IdentityRule = "name"
)

// Change is a single component-level difference between two SBOMs.
type Change struct {
	// Type is the category of the change.
	Type ChangeType `json:"type"`

	// Direction further classifies VersionChanged changes; empty for other types.
	Direction VersionChangeDirection `json:"direction,omitempty"`

	// Name is the component name, taken from the new SBOM when present, otherwise the old.
	Name string `json:"name"`

	// ComponentType is the ecosystem/package type (e.g. apk, npm, python).
	ComponentType pkg.Type `json:"componentType"`

	// PURL is the Package URL the identity was derived from, when available.
	PURL string `json:"purl,omitempty"`

	// OldVersion is the version recorded in the old SBOM; empty for Added changes.
	OldVersion string `json:"oldVersion,omitempty"`

	// NewVersion is the version recorded in the new SBOM; empty for Removed changes.
	NewVersion string `json:"newVersion,omitempty"`

	// IdentityKey is the deterministic key the component was matched on.
	IdentityKey string `json:"identityKey"`

	// IdentityRule names the rule used to build IdentityKey.
	IdentityRule IdentityRule `json:"identityRule"`

	// Unreliable is true when the match had to fall back to a non-PURL identity or to
	// an uncomparable version, so reviewers should verify the result manually.
	Unreliable bool `json:"unreliable,omitempty"`

	// OldLayer and NewLayer are the dependency-graph positions on each side.
	OldLayer Layer `json:"oldLayer,omitempty"`
	NewLayer Layer `json:"newLayer,omitempty"`

	// LayerChanged is true when the component moves between direct and transitive.
	LayerChanged bool `json:"layerChanged,omitempty"`

	// HighRisk marks changes that pipelines typically gate on: newly introduced
	// components and version downgrades.
	HighRisk bool `json:"highRisk,omitempty"`

	// Paths are the component locations, prefixed with "old=" or "new=" to show origin.
	Paths []string `json:"paths,omitempty"`
}

// IsHighRisk reports whether a change should be treated as a high-risk change.
// Added components and semantic-version downgrades are high risk by default.
func (c Change) IsHighRisk() bool {
	switch c.Type {
	case Added:
		return true
	case VersionChanged:
		return c.Direction == Downgrade
	default:
		return false
	}
}
