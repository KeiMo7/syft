package diff

import (
	"sort"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// Options controls how a diff is computed. The zero value is a valid, full diff with no
// filtering. All computation happens in memory over the two decoded SBOMs; nothing is
// written to disk.
type Options struct {
	// HighRiskOnly restricts the result to high-risk changes (added components and
	// downgrades).
	HighRiskOnly bool

	// PathPrefixes limits both inputs to components with at least one location under one
	// of the given prefixes (an empty list means no path scoping). Use this to scope a
	// diff to the directory of a single subsystem.
	PathPrefixes []string
}

// side holds the preprocessed contents of one SBOM input.
type side struct {
	byIdentity map[string][]pkg.Package
	layers     map[artifact.ID]Layer
}

// layerResolver answers the dependency-layer question for one SBOM. When the SBOM has no
// dependency-of relationships at all, every package is reported as UnknownLayer; when a
// graph exists, packages without an incoming dependency-of edge are direct dependencies.
type layerResolver struct {
	dependedOn map[artifact.ID]struct{}
	hasEdges   bool
}

// Compute returns the component-level changes from oldSBOM to newSBOM.
func Compute(oldSBOM, newSBOM sbom.SBOM, opts Options) ([]Change, error) {
	oldSide := buildSide(oldSBOM, opts.PathPrefixes)
	newSide := buildSide(newSBOM, opts.PathPrefixes)

	keys := make(map[string]struct{}, len(oldSide.byIdentity)+len(newSide.byIdentity))
	for key := range oldSide.byIdentity {
		keys[key] = struct{}{}
	}
	for key := range newSide.byIdentity {
		keys[key] = struct{}{}
	}

	var changes []Change
	for key := range keys {
		oldPackages := oldSide.byIdentity[key]
		newPackages := newSide.byIdentity[key]

		switch {
		case len(oldPackages) == 0 && len(newPackages) > 0:
			changes = append(changes, addedChange(key, newPackages, newSide))
		case len(oldPackages) > 0 && len(newPackages) == 0:
			changes = append(changes, removedChange(key, oldPackages, oldSide))
		default:
			if change := matchedChange(key, oldPackages, newPackages, oldSide, newSide); change.Type != "" {
				changes = append(changes, change)
			}
		}
	}

	sortChanges(changes)

	if opts.HighRiskOnly {
		filtered := changes[:0]
		for _, change := range changes {
			if change.IsHighRisk() {
				filtered = append(filtered, change)
			}
		}
		changes = filtered
	}

	return changes, nil
}

func buildSide(input sbom.SBOM, pathPrefixes []string) side {
	result := side{
		byIdentity: make(map[string][]pkg.Package),
		layers:     make(map[artifact.ID]Layer),
	}

	if input.Artifacts.Packages == nil {
		// an SBOM with zero components (for example an empty directory scan) still has a
		// valid structure; enumerate nothing instead of dereferencing a nil collection
		return result
	}

	resolver := layerResolver{dependedOn: make(map[artifact.ID]struct{})}
	for _, relationship := range input.Relationships {
		if relationship.Type != artifact.DependencyOfRelationship || relationship.From == nil || relationship.To == nil {
			continue
		}
		resolver.dependedOn[relationship.To.ID()] = struct{}{}
		resolver.hasEdges = true
	}

	for p := range input.Artifacts.Packages.Enumerate() {
		if !inPathScope(p, pathPrefixes) {
			continue
		}

		identity := componentIdentity(p)
		result.byIdentity[identity.key] = append(result.byIdentity[identity.key], p)

		if !resolver.hasEdges {
			result.layers[p.ID()] = UnknownLayer
			continue
		}
		if _, isDependedOn := resolver.dependedOn[p.ID()]; isDependedOn {
			result.layers[p.ID()] = TransitiveDependency
		} else {
			result.layers[p.ID()] = DirectDependency
		}
	}

	return result
}

func inPathScope(p pkg.Package, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}

	for _, location := range p.Locations.ToSlice() {
		path := locationPath(location)
		for _, prefix := range prefixes {
			if pathHasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}

// pathHasPrefix matches a component location against a scope prefix tolerating the two
// common shapes: SBOMs record locations relative to the scan root (e.g. "/subsystem/x"),
// while CI pipelines often pass the absolute working-directory prefix
// (e.g. "/work/repo/subsystem"). A match on either the literal prefix or the suffix after
// the scan-relative portion keeps both invocations working.
func pathHasPrefix(path, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	path = strings.TrimSuffix(path, "/")

	if path == prefix {
		return true
	}

	if strings.HasPrefix(path, prefix+"/") {
		return true
	}

	// absolute host prefix pointing at a scan-root-relative location: strip the host
	// directory portion by aligning on the first path segment of the SBOM location
	// (e.g. host "/work/repo/subsystem" against SBOM path "/subsystem/x").
	if idx := strings.Index(strings.TrimPrefix(path, "/"), "/"); idx > 0 {
		topSegment := path[:idx+1]
		if aligned := strings.LastIndex(prefix, topSegment); aligned >= 0 {
			return strings.HasPrefix(path, prefix[aligned:])
		}
	}

	return false
}

func locationPath(location file.Location) string {
	if path := location.AccessPath; path != "" {
		return path
	}
	return location.RealPath
}

func addedChange(key string, packages []pkg.Package, newSide side) Change {
	representative := packages[0]
	identity := componentIdentity(representative)

	change := Change{
		Type:          Added,
		Name:          representative.Name,
		ComponentType: representative.Type,
		PURL:          representative.PURL,
		NewVersion:    joinVersions(packages),
		IdentityKey:   key,
		IdentityRule:  identity.rule,
		NewLayer:      layerOf(packages, newSide),
		Paths:         collectPaths(nil, packages),
	}

	if identity.degraded() || len(packages) > 1 {
		change.Unreliable = true
	}
	change.HighRisk = change.IsHighRisk()

	return change
}

func removedChange(key string, packages []pkg.Package, oldSide side) Change {
	representative := packages[0]
	identity := componentIdentity(representative)

	change := Change{
		Type:          Removed,
		Name:          representative.Name,
		ComponentType: representative.Type,
		PURL:          representative.PURL,
		OldVersion:    joinVersions(packages),
		IdentityKey:   key,
		IdentityRule:  identity.rule,
		OldLayer:      layerOf(packages, oldSide),
		Paths:         collectPaths(packages, nil),
	}

	if identity.degraded() || len(packages) > 1 {
		change.Unreliable = true
	}

	return change
}

func matchedChange(key string, oldPackages, newPackages []pkg.Package, oldSide, newSide side) Change {
	newRepresentative := newPackages[0]
	identity := componentIdentity(newRepresentative)

	oldVersions := uniqueVersions(oldPackages)
	newVersions := uniqueVersions(newPackages)
	oldVersion := strings.Join(oldVersions, ",")
	newVersion := strings.Join(newVersions, ",")

	change := Change{
		Name:          newRepresentative.Name,
		ComponentType: newRepresentative.Type,
		PURL:          newRepresentative.PURL,
		OldVersion:    oldVersion,
		NewVersion:    newVersion,
		IdentityKey:   key,
		IdentityRule:  identity.rule,
		OldLayer:      layerOf(oldPackages, oldSide),
		NewLayer:      layerOf(newPackages, newSide),
		Paths:         collectPaths(oldPackages, newPackages),
	}

	ambiguous := len(oldPackages) > 1 || len(newPackages) > 1
	if identity.degraded() || ambiguous {
		change.Unreliable = true
	}

	if change.OldLayer != change.NewLayer {
		change.LayerChanged = true
	}

	switch {
	case oldVersion == "" || newVersion == "":
		// a missing version is a distinct category, never silently folded into "no change"
		change.Type = VersionUnknown
	case oldVersion == newVersion:
		if ambiguous {
			// multiple packages share the identity and version: surface the ambiguity
			change.Type = VersionUnknown
			break
		}
		if change.LayerChanged {
			// identical version, but the component moved between the direct and
			// transitive dependency layers
			change.Type = VersionChanged
			change.Direction = NoDirection
		} else {
			// identical component: no change to report
			return Change{}
		}
	default:
		change.Type = VersionChanged
		change.Direction = compareVersions(oldVersion, newVersion)
		if change.Direction == NoDirection {
			change.Unreliable = true
		}
	}

	change.HighRisk = change.IsHighRisk()

	return change
}

func layerOf(packages []pkg.Package, source side) Layer {
	if len(packages) == 0 {
		return UnknownLayer
	}
	if layer, ok := source.layers[packages[0].ID()]; ok {
		return layer
	}
	return UnknownLayer
}

func joinVersions(packages []pkg.Package) string {
	return strings.Join(uniqueVersions(packages), ",")
}

func uniqueVersions(packages []pkg.Package) []string {
	seen := make(map[string]struct{})
	var versions []string
	for _, p := range packages {
		if _, ok := seen[p.Version]; ok {
			continue
		}
		seen[p.Version] = struct{}{}
		versions = append(versions, p.Version)
	}
	sort.Strings(versions)
	return versions
}

func collectPaths(oldPackages, newPackages []pkg.Package) []string {
	var paths []string
	seen := make(map[string]struct{})

	add := func(prefix string, locations []file.Location) {
		for _, location := range locations {
			entry := prefix + locationPath(location)
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			paths = append(paths, entry)
		}
	}

	for _, p := range oldPackages {
		add("old=", p.Locations.ToSlice())
	}
	for _, p := range newPackages {
		add("new=", p.Locations.ToSlice())
	}

	sort.Strings(paths)
	return paths
}

func sortChanges(changes []Change) {
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].ComponentType != changes[j].ComponentType {
			return changes[i].ComponentType < changes[j].ComponentType
		}
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		if changes[i].OldVersion != changes[j].OldVersion {
			return changes[i].OldVersion < changes[j].OldVersion
		}
		return changes[i].NewVersion < changes[j].NewVersion
	})
}
