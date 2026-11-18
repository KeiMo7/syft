package trim

import (
	"reflect"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type packageSignals struct {
	categories []string
	scopes     []string
	depth      string
}

func inspectPackage(p pkg.Package, policy Policy) packageSignals {
	signals := inspectMetadata(p.Metadata)

	for _, classifier := range policy.Classifiers {
		if classifierMatches(classifier, p, signals.scopes) {
			signals.categories = append(signals.categories, classifier.Category)
		}
	}

	signals.categories = uniqueSorted(signals.categories)
	signals.scopes = uniqueSorted(signals.scopes)
	return signals
}

func classifierMatches(classifier Classifier, p pkg.Package, scopes []string) bool {
	checks := 0

	if len(classifier.PackageGlobs) > 0 {
		checks++
		if !matchesAny(classifier.PackageGlobs, []string{p.Name, p.PURL}) {
			return false
		}
	}
	if len(classifier.PathGlobs) > 0 {
		checks++
		if !matchesAny(classifier.PathGlobs, packagePaths(p)) {
			return false
		}
	}
	if len(classifier.MetadataScopes) > 0 {
		checks++
		if !matchesAny(classifier.MetadataScopes, scopes) {
			return false
		}
	}
	if len(classifier.FoundBy) > 0 {
		checks++
		if !matchesAny(classifier.FoundBy, []string{p.FoundBy}) {
			return false
		}
	}

	return checks > 0
}

func matchesAny(patterns, candidates []string) bool {
	for _, pattern := range patterns {
		for _, candidate := range candidates {
			candidate = strings.ReplaceAll(candidate, "\\", "/")
			if matched, err := doublestar.Match(pattern, candidate); err == nil && matched {
				return true
			}
		}
	}
	return false
}

func packagePaths(p pkg.Package) []string {
	var paths []string
	for _, location := range p.Locations.ToSlice() {
		paths = append(paths, location.Path(), location.LocalPath(), location.FullNestedPath())
	}
	return uniqueSorted(paths)
}

func pathExcluded(p pkg.Package, patterns []string) bool {
	if len(patterns) == 0 || p.Locations.Empty() {
		return false
	}

	locations := p.Locations.ToSlice()
	if len(locations) == 0 {
		return false
	}

	for _, location := range locations {
		candidates := []string{location.Path(), location.LocalPath(), location.FullNestedPath()}
		if !matchesAny(patterns, candidates) {
			return false
		}
	}
	return true
}

func inspectMetadata(metadata any) packageSignals {
	var signals packageSignals
	walkMetadata(reflect.ValueOf(metadata), 0, make(map[uintptr]struct{}), &signals)
	signals.categories = uniqueSorted(signals.categories)
	signals.scopes = uniqueSorted(signals.scopes)
	return signals
}

func walkMetadata(value reflect.Value, depth int, seen map[uintptr]struct{}, signals *packageSignals) {
	if depth > 4 || !value.IsValid() {
		return
	}

	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return
		}
		if value.Kind() == reflect.Pointer {
			ptr := value.Pointer()
			if ptr != 0 {
				if _, ok := seen[ptr]; ok {
					return
				}
				seen[ptr] = struct{}{}
			}
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return
	}

	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}

		name := normalizeFieldName(field.Name)
		if name == "parent" {
			continue
		}

		fieldValue := value.Field(i)
		switch fieldValue.Kind() {
		case reflect.Bool:
			if fieldValue.Bool() {
				applyBoolSignal(name, signals)
			}
		case reflect.String:
			applyStringSignal(name, fieldValue.String(), signals)
		case reflect.Pointer, reflect.Interface, reflect.Struct:
			walkMetadata(fieldValue, depth+1, seen, signals)
		}
	}
}

func normalizeFieldName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "")
	name = strings.ReplaceAll(name, "-", "")
	return name
}

func applyBoolSignal(name string, signals *packageSignals) {
	switch {
	case name == "dev" || name == "development" || name == "isdev" || name == "devonly" || name == "devdependency":
		signals.categories = append(signals.categories, CategoryDev)
	case name == "test" || name == "istest" || name == "testonly" || name == "testdependency":
		signals.categories = append(signals.categories, CategoryTest)
	case name == "build" || name == "isbuild" || name == "buildonly" || name == "buildtime" || name == "buildtool":
		signals.categories = append(signals.categories, CategoryBuild)
	case name == "direct" || name == "isdirect":
		signals.depth = "direct"
	case name == "transitive" || name == "istransitive" || name == "indirect":
		signals.depth = "transitive"
	}
}

func applyStringSignal(name, value string, signals *packageSignals) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return
	}

	switch {
	case strings.Contains(name, "scope"):
		signals.scopes = append(signals.scopes, normalized)
		switch normalized {
		case "dev", "development", "develop", "dev-only", "devonly":
			signals.categories = append(signals.categories, CategoryDev)
		case "test", "tests", "testing", "test-only", "testonly":
			signals.categories = append(signals.categories, CategoryTest)
		case "build", "build-time", "buildtime", "provided":
			signals.categories = append(signals.categories, CategoryBuild)
		case "runtime", "compile", "provided-runtime":
			signals.categories = append(signals.categories, "runtime")
		}
	case name == "dependencytype" || name == "dependencykind" || name == "type":
		switch normalized {
		case "direct":
			signals.depth = "direct"
		case "transitive", "centraltransitive", "indirect":
			signals.depth = "transitive"
		case "dev", "development":
			signals.categories = append(signals.categories, CategoryDev)
		case "test", "testing":
			signals.categories = append(signals.categories, CategoryTest)
		case "build", "buildtime", "build-time":
			signals.categories = append(signals.categories, CategoryBuild)
		}
	}
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

type dependencyDepth struct {
	direct     map[artifact.ID]struct{}
	transitive map[artifact.ID]struct{}
	unknown    map[artifact.ID]struct{}
}

func analyzeDepth(packages []pkg.Package, relationships []artifact.Relationship) dependencyDepth {
	out := dependencyDepth{
		direct:     make(map[artifact.ID]struct{}),
		transitive: make(map[artifact.ID]struct{}),
		unknown:    make(map[artifact.ID]struct{}),
	}

	childrenByParent := make(map[artifact.ID][]artifact.ID)
	hasOutgoing := make(map[artifact.ID]struct{})
	appearsInGraph := make(map[artifact.ID]struct{})
	pkgIDs := make(map[artifact.ID]struct{}, len(packages))
	for _, p := range packages {
		pkgIDs[p.ID()] = struct{}{}
	}

	for _, relationship := range relationships {
		if relationship.Type != artifact.DependencyOfRelationship {
			continue
		}
		child, childOK := asPackage(relationship.From)
		parent, parentOK := asPackage(relationship.To)
		if !childOK || !parentOK {
			continue
		}
		if _, ok := pkgIDs[child.ID()]; !ok {
			continue
		}
		if _, ok := pkgIDs[parent.ID()]; !ok {
			continue
		}
		childrenByParent[parent.ID()] = append(childrenByParent[parent.ID()], child.ID())
		hasOutgoing[child.ID()] = struct{}{}
		appearsInGraph[child.ID()] = struct{}{}
		appearsInGraph[parent.ID()] = struct{}{}
	}

	var queue []artifact.ID
	for _, p := range packages {
		_, connected := appearsInGraph[p.ID()]
		_, hasDependency := hasOutgoing[p.ID()]
		if connected && !hasDependency {
			out.direct[p.ID()] = struct{}{}
			queue = append(queue, p.ID())
		}
	}

	// Breadth-first traversal from top-level packages: one hop is direct, anything deeper is
	// transitive. The BFS keeps the shortest distance when the graph contains multiple paths.
	depth := make(map[artifact.ID]int, len(packages))
	for _, id := range queue {
		depth[id] = 0
	}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range childrenByParent[parent] {
			nextDepth := depth[parent] + 1
			if current, ok := depth[child]; ok && current <= nextDepth {
				continue
			}
			depth[child] = nextDepth
			queue = append(queue, child)
		}
	}

	for id, value := range depth {
		if value <= 1 {
			out.direct[id] = struct{}{}
		} else {
			out.transitive[id] = struct{}{}
		}
	}

	// A package that is never reachable from a top-level node cannot be proven direct or
	// transitive. Callers retain and count it as unknown.
	for _, p := range packages {
		if _, ok := depth[p.ID()]; !ok {
			out.unknown[p.ID()] = struct{}{}
		}
	}

	return out
}

func asPackage(value artifact.Identifiable) (pkg.Package, bool) {
	switch typed := value.(type) {
	case pkg.Package:
		return typed, true
	case *pkg.Package:
		if typed != nil {
			return *typed, true
		}
	}
	return pkg.Package{}, false
}

func normalizeImageCandidate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	if scheme := strings.Index(value, "://"); scheme >= 0 {
		value = value[scheme+3:]
	} else if colon := strings.Index(value, ":"); colon > 0 && !strings.Contains(value[:colon], "/") {
		switch value[:colon] {
		case "docker", "podman", "registry", "dir", "file":
			value = value[colon+1:]
		}
	}
	if at := strings.LastIndex(value, "@"); at > strings.LastIndex(value, "/") {
		value = value[:at]
	}
	return strings.TrimPrefix(value, "/")
}

func imageCandidates(description source.Description) []string {
	candidates := []string{description.Name, description.Name + ":" + description.Version}
	if description.Version == "" {
		candidates = candidates[:1]
	}

	switch metadata := description.Metadata.(type) {
	case source.ImageMetadata:
		candidates = append(candidates, metadata.UserInput, metadata.ID)
		candidates = append(candidates, metadata.Tags...)
		candidates = append(candidates, metadata.RepoDigests...)
	case source.OCIModelMetadata:
		image := source.ImageMetadata(metadata)
		candidates = append(candidates, image.UserInput, image.ID)
		candidates = append(candidates, image.Tags...)
		candidates = append(candidates, image.RepoDigests...)
	}

	normalized := make([]string, 0, len(candidates)*2)
	for _, candidate := range candidates {
		candidate = normalizeImageCandidate(candidate)
		if candidate != "" {
			normalized = append(normalized, candidate)
		}
	}
	return uniqueSorted(normalized)
}

func matchesImagePatterns(patterns []string, description source.Description) bool {
	return matchesAny(patterns, imageCandidates(description))
}
