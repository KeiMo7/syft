// Package incremental implements content-based incremental cataloging support.
//
// The package deliberately does not depend on any package cataloger. It compares a
// previous SBOM with the files visible in the current source, filters cataloger
// discovery to changed paths, and merges the newly discovered packages with
// packages that can safely be carried over from the previous SBOM.
package incremental

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	// OriginAnnotationKey records whether a package was discovered by this run or
	// carried over from the reference SBOM. The annotation is attached to package
	// locations so the existing package and SBOM schemas remain unchanged.
	OriginAnnotationKey = "syft:incremental:origin"

	// OriginCurrent marks a package discovered by the current cataloging run.
	OriginCurrent = "current"

	// OriginReused marks a package carried over from the reference SBOM.
	OriginReused = "reused"
)

// Mode describes how the SBOM should be produced.
type Mode string

const (
	// ModeFull means the caller must perform a normal full catalog.
	ModeFull Mode = "full"

	// ModeIncremental means only changed paths need to be cataloged.
	ModeIncremental Mode = "incremental"
)

// SourceOverride lets a caller override the source compatibility decision.
//
// The bool result is the compatibility decision and the second bool indicates
// whether the override applies. This is useful for registries which rewrite a
// manifest without changing image content.
type SourceOverride func(baseline, current source.Description) (compatible bool, applied bool)

// Options controls change detection.
type Options struct {
	// ForceFull disables incremental processing.
	ForceFull bool

	// SourceOverride can force the source compatibility decision. An override
	// cannot hide path-level differences: even when sources are considered
	// compatible, every path is still compared by content.
	SourceOverride SourceOverride
}

// LayerChangeKind describes a layer-level difference.
type LayerChangeKind string

const (
	LayerAdded    LayerChangeKind = "added"
	LayerRemoved  LayerChangeKind = "removed"
	LayerReplaced LayerChangeKind = "replaced"
)

// LayerChange describes a layer added to, removed from, or replaced in the
// current image relative to the reference image.
type LayerChange struct {
	Kind     LayerChangeKind
	Index    int
	Previous string
	Current  string
}

type fingerprint struct {
	kind   string
	link   string
	digest string
}

func (f fingerprint) equal(other fingerprint) bool {
	return f == other
}

func (f fingerprint) valid() bool {
	if f.kind == "regular" {
		return f.digest != ""
	}
	return f.kind != ""
}

type inventory map[string][]fingerprint
type coordinateInventory map[file.Coordinates]fingerprint

// Plan is the result of comparing a reference SBOM with the current source.
type Plan struct {
	// Mode is the decision for this run.
	Mode Mode

	// Reason explains a full fallback.
	Reason string

	// ChangedPaths is the sorted set of paths added, removed, or changed.
	ChangedPaths []string

	// LayerChanges describes image layer differences.
	LayerChanges []LayerChange

	// Warnings contains non-fatal change-detection problems. A path mentioned by
	// a warning is always treated as changed.
	Warnings []string

	current   inventory
	reference inventory
	changed   map[string]struct{}
}

// ChangedPathSet returns the changed paths as a set.
func (p Plan) ChangedPathSet() map[string]struct{} {
	out := make(map[string]struct{}, len(p.changed))
	for path := range p.changed {
		out[path] = struct{}{}
	}
	return out
}

// UnchangedPathCount returns the number of reference paths that can be reused.
func (p Plan) UnchangedPathCount() int {
	if p.Mode != ModeIncremental {
		return 0
	}
	count := 0
	for path := range p.reference {
		if _, changed := p.changed[path]; !changed {
			if _, current := p.current[path]; current {
				count++
			}
		}
	}
	return count
}

// TotalReferencePathCount returns the number of paths in the reference SBOM.
func (p Plan) TotalReferencePathCount() int {
	return len(p.reference)
}

// Analyze compares the reference SBOM with the current source.
//
// A missing or incompatible baseline is not an error: it produces a full-scan
// plan with a reason. Per-path hashing failures are also non-fatal and force the
// affected path to be cataloged in full.
func Analyze(ctx context.Context, baseline *sbom.SBOM, current source.Description, resolver file.Resolver, opts Options) (Plan, error) {
	if opts.ForceFull {
		return fullPlan("incremental processing was explicitly disabled"), nil
	}
	if baseline == nil {
		return fullPlan("reference SBOM is missing"), nil
	}
	if resolver == nil {
		return fullPlan("file resolver is unavailable"), nil
	}

	compatible, reason := compatibleSource(baseline.Source, current, opts.SourceOverride)
	if !compatible {
		return fullPlan(reason), nil
	}

	reference, referenceCoords := inventoryFromSBOM(baseline)
	currentInv, warnings, err := inventoryFromResolver(ctx, resolver, referenceCoords, unchangedLayers(baseline.Source, current))
	if err != nil {
		return Plan{}, err
	}
	if len(currentInv) == 0 {
		return fullPlan("unable to enumerate files in the current source"), nil
	}

	changed := changedPaths(reference, currentInv)
	expandArchiveChanges(changed, reference, currentInv)

	plan := Plan{
		Mode:         ModeIncremental,
		ChangedPaths: sortedSet(changed),
		LayerChanges: diffLayers(layerMetadata(baseline.Source), layerMetadata(current)),
		Warnings:     warnings,
		current:      currentInv,
		reference:    reference,
		changed:      changed,
	}

	if len(changed) == 0 {
		plan.Reason = "all paths have identical content"
	}

	return plan, nil
}

func fullPlan(reason string) Plan {
	return Plan{
		Mode:   ModeFull,
		Reason: reason,
	}
}

func inventoryFromSBOM(s *sbom.SBOM) (inventory, coordinateInventory) {
	inv := make(inventory)
	coords := make(coordinateInventory)

	coordinates := make(map[file.Coordinates]struct{}, len(s.Artifacts.FileMetadata)+len(s.Artifacts.FileDigests))
	for coordinate := range s.Artifacts.FileMetadata {
		coordinates[coordinate] = struct{}{}
	}
	for coordinate := range s.Artifacts.FileDigests {
		coordinates[coordinate] = struct{}{}
	}

	for coordinate := range coordinates {
		fp, ok := fingerprintFromSBOM(s, coordinate)
		if !ok {
			continue
		}
		coords[coordinate] = fp
		path := coordinate.FullNestedPath()
		inv[path] = appendUniqueFingerprint(inv[path], fp)
	}

	for path := range inv {
		inv[path] = sortFingerprints(inv[path])
	}

	return inv, coords
}

func fingerprintFromSBOM(s *sbom.SBOM, coordinate file.Coordinates) (fingerprint, bool) {
	metadata, hasMetadata := s.Artifacts.FileMetadata[coordinate]
	digests, hasDigests := s.Artifacts.FileDigests[coordinate]

	if hasMetadata && metadata.Type != 0 {
		switch metadata.Type.String() {
		case "RegularFile":
			digest, ok := findDigest(digests, "sha256")
			if !ok {
				return fingerprint{}, false
			}
			return fingerprint{kind: "regular", digest: digest}, true
		case "SymbolicLink", "HardLink":
			if metadata.LinkDestination == "" {
				return fingerprint{}, false
			}
			return fingerprint{kind: "link", link: metadata.LinkDestination}, true
		case "Directory":
			return fingerprint{kind: "directory"}, true
		default:
			return fingerprint{kind: "other", link: metadata.Type.String()}, true
		}
	}

	if hasDigests {
		digest, ok := findDigest(digests, "sha256")
		if !ok {
			return fingerprint{}, false
		}
		return fingerprint{kind: "regular", digest: digest}, true
	}

	return fingerprint{}, false
}

func findDigest(digests []file.Digest, algorithm string) (string, bool) {
	algorithm = normalizeDigestName(algorithm)
	for _, digest := range digests {
		if normalizeDigestName(digest.Algorithm) == algorithm && digest.Value != "" {
			return digest.Value, true
		}
	}
	return "", false
}

func normalizeDigestName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "")
	return name
}

func appendUniqueFingerprint(values []fingerprint, value fingerprint) []fingerprint {
	for _, candidate := range values {
		if candidate.equal(value) {
			return values
		}
	}
	return append(values, value)
}

func sortFingerprints(values []fingerprint) []fingerprint {
	sort.Slice(values, func(i, j int) bool {
		if values[i].kind != values[j].kind {
			return values[i].kind < values[j].kind
		}
		if values[i].link != values[j].link {
			return values[i].link < values[j].link
		}
		return values[i].digest < values[j].digest
	})
	return values
}

func changedPaths(reference, current inventory) map[string]struct{} {
	changed := make(map[string]struct{})

	for path, referenceFingerprints := range reference {
		currentFingerprints, exists := current[path]
		if !exists || !sameFingerprints(referenceFingerprints, currentFingerprints) {
			changed[path] = struct{}{}
		}
	}
	for path := range current {
		if _, exists := reference[path]; !exists {
			changed[path] = struct{}{}
		}
	}

	return changed
}

func sameFingerprints(left, right []fingerprint) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !left[i].equal(right[i]) {
			return false
		}
	}
	return true
}

// expandArchiveChanges marks reference paths contained in a changed archive as
// changed as well. Archive paths use the syft "!/" separator.
func expandArchiveChanges(changed map[string]struct{}, reference, current inventory) {
	for path := range changed {
		prefix := path + file.ArchivePathSeparator
		for referencePath := range reference {
			if strings.HasPrefix(referencePath, prefix) {
				changed[referencePath] = struct{}{}
			}
		}
		for currentPath := range current {
			if strings.HasPrefix(currentPath, prefix) {
				changed[currentPath] = struct{}{}
			}
		}
	}
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func layerMetadata(description source.Description) []source.LayerMetadata {
	switch metadata := description.Metadata.(type) {
	case source.ImageMetadata:
		return metadata.Layers
	case *source.ImageMetadata:
		if metadata != nil {
			return metadata.Layers
		}
	}
	return nil
}

func diffLayers(previous, current []source.LayerMetadata) []LayerChange {
	var changes []LayerChange

	previousByDigest := make(map[string]int, len(previous))
	for i, layer := range previous {
		previousByDigest[layer.Digest] = i
	}
	currentByDigest := make(map[string]int, len(current))
	for i, layer := range current {
		currentByDigest[layer.Digest] = i
	}

	for i, layer := range current {
		if _, exists := previousByDigest[layer.Digest]; exists {
			continue
		}
		kind := LayerAdded
		var prior string
		if i < len(previous) {
			kind = LayerReplaced
			prior = previous[i].Digest
		}
		changes = append(changes, LayerChange{Kind: kind, Index: i, Previous: prior, Current: layer.Digest})
	}

	for i, layer := range previous {
		if _, exists := currentByDigest[layer.Digest]; exists {
			continue
		}
		if i < len(current) {
			if _, alreadyReported := findReplacement(changes, layer.Digest); alreadyReported {
				continue
			}
		}
		changes = append(changes, LayerChange{Kind: LayerRemoved, Index: i, Previous: layer.Digest})
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Index != changes[j].Index {
			return changes[i].Index < changes[j].Index
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes
}

func findReplacement(changes []LayerChange, previousDigest string) (LayerChange, bool) {
	for _, change := range changes {
		if change.Kind == LayerReplaced && change.Previous == previousDigest {
			return change, true
		}
	}
	return LayerChange{}, false
}

func unchangedLayers(baseline source.Description, current source.Description) map[string]struct{} {
	previous := layerMetadata(baseline)
	if len(previous) == 0 {
		return nil
	}
	currentByDigest := make(map[string]struct{}, len(layerMetadata(current)))
	for _, layer := range layerMetadata(current) {
		currentByDigest[layer.Digest] = struct{}{}
	}

	unchanged := make(map[string]struct{})
	for _, layer := range previous {
		if _, exists := currentByDigest[layer.Digest]; exists {
			unchanged[layer.Digest] = struct{}{}
		}
	}
	return unchanged
}

func compatibleSource(baseline, current source.Description, override SourceOverride) (bool, string) {
	if override != nil {
		if compatible, applied := override(baseline, current); applied {
			if compatible {
				return true, "source compatibility overridden by caller"
			}
			return false, "source compatibility rejected by caller"
		}
	}

	if baseline.ID != "" && current.ID != "" && baseline.ID == current.ID {
		return true, "source IDs match"
	}

	baselineImage, baselineIsImage := imageMetadata(baseline)
	currentImage, currentIsImage := imageMetadata(current)
	if baselineIsImage || currentIsImage {
		if !baselineIsImage || !currentIsImage {
			return false, "reference SBOM source type differs from the current source"
		}
		if imageContentEqual(baselineImage, currentImage) {
			return true, "image content identity matches"
		}
		baselineFamily := imageFamily(baseline, baselineImage)
		currentFamily := imageFamily(current, currentImage)
		if baselineFamily != "" && baselineFamily == currentFamily {
			return true, "image repository matches"
		}
		return false, "reference SBOM belongs to a different image"
	}

	baselineType := sourceType(baseline)
	currentType := sourceType(current)
	if baselineType == "" || currentType == "" || baselineType != currentType {
		return false, "reference SBOM source type differs from the current source"
	}

	return false, "reference SBOM source does not match the current source"
}

func imageMetadata(description source.Description) (source.ImageMetadata, bool) {
	switch metadata := description.Metadata.(type) {
	case source.ImageMetadata:
		return metadata, true
	case *source.ImageMetadata:
		if metadata != nil {
			return *metadata, true
		}
	}
	return source.ImageMetadata{}, false
}

func imageContentEqual(left, right source.ImageMetadata) bool {
	if left.ManifestDigest != "" && right.ManifestDigest != "" {
		return left.ManifestDigest == right.ManifestDigest
	}
	if len(left.RawManifest) > 0 && len(right.RawManifest) > 0 {
		return string(left.RawManifest) == string(right.RawManifest)
	}
	if left.ID != "" && right.ID != "" && left.ID != right.ID {
		return false
	}
	if len(left.Layers) != len(right.Layers) {
		return false
	}
	for i := range left.Layers {
		if left.Layers[i].Digest != right.Layers[i].Digest {
			return false
		}
	}
	return left.ID != "" && right.ID != ""
}

func imageFamily(description source.Description, metadata source.ImageMetadata) string {
	if description.Name != "" {
		return description.Name
	}
	if metadata.UserInput != "" {
		return imageRepositoryFromReference(metadata.UserInput)
	}
	for _, repoDigest := range metadata.RepoDigests {
		if repository := imageRepositoryFromReference(repoDigest); repository != "" {
			return repository
		}
	}
	return ""
}

func imageRepositoryFromReference(reference string) string {
	if before, _, found := strings.Cut(reference, "@"); found {
		return before
	}
	lastSlash := strings.LastIndex(reference, "/")
	lastColon := strings.LastIndex(reference, ":")
	if lastColon > lastSlash {
		return reference[:lastColon]
	}
	return reference
}

func sourceType(description source.Description) string {
	switch description.Metadata.(type) {
	case source.DirectoryMetadata, *source.DirectoryMetadata:
		return "directory"
	case source.FileMetadata, *source.FileMetadata:
		return "file"
	}
	return ""
}

// MergeStats summarizes an incremental merge.
type MergeStats struct {
	Mode             Mode
	TotalPaths       int
	ChangedPaths     int
	ReusedPaths      int
	ParsedPackages   int
	ReusedPackages   int
	TotalPackages    int
	ReuseRatio       float64
	LayerChanges     int
	FallbackRequired bool
}

// MergeResult is the outcome of merging current findings with a reference SBOM.
type MergeResult struct {
	SBOM   *sbom.SBOM
	Stats  MergeStats
	Reason string
}

// Merge carries unchanged packages and file facts forward from the reference
// SBOM. If a package cannot be safely mapped to paths, or if a package expected
// from a still-present path was not rediscovered, merge asks the caller to retry
// with a full scan instead of silently dropping the component.
//
//nolint:funlen
func Merge(reference, current *sbom.SBOM, plan Plan) MergeResult {
	if reference == nil || current == nil || plan.Mode != ModeIncremental {
		if current == nil {
			return MergeResult{Reason: "current SBOM is missing"}
		}
		markCurrentPackages(current)
		return MergeResult{
			SBOM: current,
			Stats: MergeStats{
				Mode:           ModeFull,
				ParsedPackages: current.Artifacts.Packages.PackageCount(),
				TotalPackages:  current.Artifacts.Packages.PackageCount(),
			},
		}
	}

	result := cloneArtifactMaps(current)
	result.Source = current.Source
	result.Descriptor = current.Descriptor
	result.Relationships = append([]artifactRelationship(nil), current.Relationships...)

	currentPackages := packagesByID(current)
	referencePackages := packagesByID(reference)
	currentPackagePaths := packagePathCoverage(current)
	finalPackages := pkgCollection()

	for _, p := range currentPackages {
		finalPackages.Add(withPackageOrigin(p, OriginCurrent))
	}

	changed := plan.changed
	reused := make(map[string]pkgPackage)
	fallbackReason := ""
	missingReuse := make([]string, 0)

	for id, referencePackage := range referencePackages {
		paths := packagePaths(reference, referencePackage)
		if len(paths) == 0 {
			if _, parsed := currentPackages[id]; !parsed {
				fallbackReason = fmt.Sprintf("reference package %s has no usable source path", referencePackage.String())
				break
			}
			continue
		}

		if pathSetHasExisting(paths, plan.current) && pathsRemainUnchanged(paths, changed, plan.current, plan.reference) {
			reused[id] = referencePackage
			continue
		}

		if _, parsed := currentPackages[id]; parsed {
			continue
		}

		if hasUncoveredExistingPath(paths, plan.current, currentPackagePaths) {
			missingReuse = append(missingReuse, referencePackage.String())
		}
	}

	if fallbackReason == "" && len(missingReuse) > 0 {
		fallbackReason = fmt.Sprintf("reference packages were not rediscovered from changed paths: %s", strings.Join(missingReuse, ", "))
	}

	if fallbackReason != "" {
		markCurrentPackages(current)
		return MergeResult{
			SBOM:   current,
			Reason: fallbackReason,
			Stats: MergeStats{
				Mode:             ModeFull,
				TotalPaths:       plan.TotalReferencePathCount(),
				ChangedPaths:     len(plan.ChangedPaths),
				ParsedPackages:   len(currentPackages),
				TotalPackages:    len(currentPackages),
				LayerChanges:     len(plan.LayerChanges),
				FallbackRequired: true,
			},
		}
	}

	for _, referencePackage := range reused {
		finalPackages.Add(withPackageOrigin(referencePackage, OriginReused))
	}

	result.Artifacts.Packages = finalPackages
	result.Artifacts = mergeArtifactMaps(result.Artifacts, reference.Artifacts, changed)
	result.Relationships = mergeRelationships(result.Relationships, reference.Relationships, result.Artifacts.Packages, plan.current, changed)
	if result.Artifacts.LinuxDistribution == nil {
		result.Artifacts.LinuxDistribution = reference.Artifacts.LinuxDistribution
	}

	totalPackages := finalPackages.PackageCount()
	reusedCount := 0
	for id := range reused {
		if _, parsed := currentPackages[id]; !parsed {
			reusedCount++
		}
	}
	ratio := 0.0
	if totalPackages > 0 {
		ratio = float64(reusedCount) / float64(totalPackages)
	}

	return MergeResult{
		SBOM: &result,
		Stats: MergeStats{
			Mode:           ModeIncremental,
			TotalPaths:     plan.TotalReferencePathCount(),
			ChangedPaths:   len(plan.ChangedPaths),
			ReusedPaths:    plan.UnchangedPathCount(),
			ParsedPackages: len(currentPackages),
			ReusedPackages: reusedCount,
			TotalPackages:  totalPackages,
			ReuseRatio:     ratio,
			LayerChanges:   len(plan.LayerChanges),
		},
	}
}

func packagesByID(s *sbom.SBOM) map[string]pkgPackage {
	out := make(map[string]pkgPackage)
	if s == nil || s.Artifacts.Packages == nil {
		return out
	}
	for p := range s.Artifacts.Packages.Enumerate() {
		out[string(p.ID())] = p
	}
	return out
}

func packagePaths(s *sbom.SBOM, p pkgPackage) []string {
	set := make(map[string]struct{})
	for _, location := range p.Locations.ToSlice() {
		set[location.FullNestedPath()] = struct{}{}
	}

	for _, relationship := range s.Relationships {
		if relationship.From == nil || relationship.To == nil {
			continue
		}
		var coordinates file.Coordinates
		var ok bool

		switch {
		case relationship.From.ID() == p.ID():
			coordinates, ok = coordinatesOf(relationship.To)
		case relationship.To.ID() == p.ID():
			coordinates, ok = coordinatesOf(relationship.From)
		}
		if ok {
			set[coordinates.FullNestedPath()] = struct{}{}
		}
	}

	paths := make([]string, 0, len(set))
	for path := range set {
		if path != "" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

func coordinatesOf(identifiable interface{ ID() artifactID }) (file.Coordinates, bool) {
	switch value := any(identifiable).(type) {
	case file.Coordinates:
		return value, true
	case *file.Coordinates:
		if value != nil {
			return *value, true
		}
	}
	return file.Coordinates{}, false
}

func pathSetHasExisting(paths []string, current inventory) bool {
	for _, path := range paths {
		if _, exists := current[path]; exists {
			return true
		}
	}
	return false
}

func hasUncoveredExistingPath(paths []string, current inventory, covered map[string]struct{}) bool {
	for _, path := range paths {
		if _, exists := current[path]; !exists {
			continue
		}
		if _, found := covered[path]; !found {
			return true
		}
	}
	return false
}

func packagePathCoverage(s *sbom.SBOM) map[string]struct{} {
	covered := make(map[string]struct{})
	if s == nil || s.Artifacts.Packages == nil {
		return covered
	}
	for p := range s.Artifacts.Packages.Enumerate() {
		for _, location := range p.Locations.ToSlice() {
			covered[location.FullNestedPath()] = struct{}{}
		}
	}
	for _, relationship := range s.Relationships {
		if relationship.From == nil || relationship.To == nil {
			continue
		}
		_, fromPackage := relationship.From.(pkgPackage)
		_, toPackage := relationship.To.(pkgPackage)
		if !fromPackage && !toPackage {
			continue
		}
		if coordinates, ok := coordinatesOf(relationship.From); ok {
			covered[coordinates.FullNestedPath()] = struct{}{}
		}
		if coordinates, ok := coordinatesOf(relationship.To); ok {
			covered[coordinates.FullNestedPath()] = struct{}{}
		}
	}
	return covered
}

func pathsRemainUnchanged(paths []string, changed map[string]struct{}, current, reference inventory) bool {
	for _, path := range paths {
		if _, isChanged := changed[path]; isChanged {
			return false
		}
		if isDirectoryPath(path, current) || isDirectoryPath(path, reference) {
			prefix := path + "/"
			for changedPath := range changed {
				if strings.HasPrefix(changedPath, prefix) {
					return false
				}
			}
		}
	}
	return true
}

func isDirectoryPath(path string, inv inventory) bool {
	for _, fp := range inv[path] {
		if fp.kind == "directory" {
			return true
		}
	}
	return false
}

func withPackageOrigin(p pkgPackage, origin string) pkgPackage {
	locations := file.NewLocationSet()
	for _, location := range p.Locations.ToSlice() {
		locations.Add(location.WithAnnotation(OriginAnnotationKey, origin))
	}
	p.Locations = locations
	return p
}

func markCurrentPackages(s *sbom.SBOM) {
	if s == nil || s.Artifacts.Packages == nil {
		return
	}
	packages := pkgCollection()
	for p := range s.Artifacts.Packages.Enumerate() {
		packages.Add(withPackageOrigin(p, OriginCurrent))
	}
	s.Artifacts.Packages = packages
}

func mergeRelationships(current, reference []artifactRelationship, packages packageLister, currentInventory inventory, changed map[string]struct{}) []artifactRelationship {
	out := append([]artifactRelationship(nil), current...)
	seen := make(map[string]struct{}, len(out))
	for _, relationship := range out {
		seen[relationshipKey(relationship)] = struct{}{}
	}

	for _, relationship := range reference {
		if relationship.From == nil || relationship.To == nil {
			continue
		}
		if !relationshipEndpointsPresent(relationship, packages, currentInventory, changed) {
			continue
		}
		key := relationshipKey(relationship)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, relationship)
	}
	return out
}

func relationshipEndpointsPresent(relationship artifactRelationship, packages packageLister, currentInventory inventory, changed map[string]struct{}) bool {
	for _, endpoint := range []identifiable{relationship.From, relationship.To} {
		if endpoint == nil {
			return false
		}
		if coordinates, ok := coordinatesOf(endpoint); ok {
			if _, exists := currentInventory[coordinates.FullNestedPath()]; !exists {
				return false
			}
			if _, isChanged := changed[coordinates.FullNestedPath()]; isChanged {
				return false
			}
			continue
		}
		if packages.Package(endpoint.ID()) == nil {
			return false
		}
	}
	return true
}

func relationshipKey(relationship artifactRelationship) string {
	return fmt.Sprintf("%s|%s|%s|%#v", relationship.From.ID(), relationship.To.ID(), relationship.Type, relationship.Data)
}

func mergeArtifactMaps(current, reference artifactMaps, changed map[string]struct{}) artifactMaps {
	current.FileMetadata = mergeMap(current.FileMetadata, reference.FileMetadata, changed)
	current.FileDigests = mergeMap(current.FileDigests, reference.FileDigests, changed)
	current.FileContents = mergeMap(current.FileContents, reference.FileContents, changed)
	current.FileLicenses = mergeMap(current.FileLicenses, reference.FileLicenses, changed)
	current.Executables = mergeMap(current.Executables, reference.Executables, changed)
	current.Unknowns = mergeMap(current.Unknowns, reference.Unknowns, changed)
	return current
}

func mergeMap[T any](current, reference map[file.Coordinates]T, changed map[string]struct{}) map[file.Coordinates]T {
	if current == nil {
		current = make(map[file.Coordinates]T)
	}
	for coordinate, value := range reference {
		path := coordinate.FullNestedPath()
		if _, isChanged := changed[path]; isChanged {
			continue
		}
		if _, exists := current[coordinate]; exists {
			continue
		}
		current[coordinate] = value
	}
	return current
}

func cloneArtifactMaps(s *sbom.SBOM) sbom.SBOM {
	out := *s
	out.Artifacts = s.Artifacts
	out.Artifacts.Packages = pkgCollection()
	out.Relationships = nil
	return out
}
