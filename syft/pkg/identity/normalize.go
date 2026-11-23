// Package identity defines the rules that decide whether two package records describe the same
// component, and merges those records into a single entry while retaining every piece of evidence.
//
// The package is deliberately self-contained: identity is computed from the package data alone
// (no database, no network), and every decision is recorded in a report so a reviewer can see
// which rule matched, which values conflicted, and what was kept.
package identity

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/anchore/syft/syft/pkg"
)

// Rule identifiers. Every equivalence in the report cites at least one of these.
const (
	// name rules
	RuleNameExact         = "name.exact"
	RuleNameCaseFold      = "name.case-fold"
	RuleNameSeparatorFold = "name.separator-fold"
	RuleNameNamespaceFold = "name.namespace-fold"

	// version rules
	RuleVersionExact    = "version.exact"
	RuleVersionSemver   = "version.semver-canonical"
	RuleVersionRevision = "version.revision-variant"

	// structural rules
	RuleTypeExact   = "type.exact"
	RulePURLAgrees  = "purl.agrees"
	RuleNoMergeType = "type.distinct-no-merge"
)

// separatorRun folds every run of hyphens, underscores and dots into a single hyphen. This is the
// PEP 503 convention and also the convention package URLs use for their name component, so it
// applies to every ecosystem rather than just Python: `foo_bar`, `foo-bar` and `foo.bar` are all
// the same component name.
var separatorRun = regexp.MustCompile(`[-_.]+`)

// epochPrefix matches the Debian/RPM/ALPM epoch, e.g. the "2:" in "2:1.0-1".
var epochPrefix = regexp.MustCompile(`^\d+:`)

// osTypes are the ecosystems whose version string carries a package-manager revision after the
// upstream version (Debian: 1.2.3-1, Alpine: 1.2.3-r0, RPM: 1.2.3-1.el9). Only for these types do
// we treat "with revision" and "without revision" as the same upstream component.
var osTypes = map[pkg.Type]bool{
	pkg.DebPkg:     true,
	pkg.RpmPkg:     true,
	pkg.ApkPkg:     true,
	pkg.AlpmPkg:    true,
	pkg.PortagePkg: true,
}

// splitName separates a namespace prefix from the component name. It understands the npm scoped
// form (`@scope/name`) and any path-like prefix (`github.com/acme/tool`), which is how Go module
// paths and purl namespaces are written. The namespace is returned without the leading `@`.
func splitName(raw string) (namespace, name string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}

	if strings.HasPrefix(s, "@") {
		if i := strings.Index(s, "/"); i > 0 {
			return strings.TrimPrefix(s[:i], "@"), s[i+1:]
		}
		return "", strings.TrimPrefix(s, "@")
	}

	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[:i], s[i+1:]
	}

	return "", s
}

// foldSeparators applies the separator folding rule and trims the hyphen it may leave at either end.
func foldSeparators(s string) string {
	return strings.Trim(separatorRun.ReplaceAllString(s, "-"), "-")
}

// stripEpoch removes a Debian/RPM/ALPM epoch prefix from a version.
func stripEpoch(version string) string {
	return epochPrefix.ReplaceAllString(strings.TrimSpace(version), "")
}

// normalizeName returns the canonical namespace and name for a raw package name. The rules that
// changed the spelling are returned so the report can cite them.
func normalizeName(raw string) (namespace, name string, applied []string) {
	ns, base := splitName(raw)

	lowerBase := strings.ToLower(base)
	lowerNS := strings.ToLower(strings.TrimPrefix(ns, "@"))

	foldedBase := foldSeparators(lowerBase)
	foldedNS := foldSeparators(lowerNS)

	if strings.HasPrefix(strings.TrimSpace(raw), "@") {
		applied = append(applied, RuleNameNamespaceFold)
	}
	if lowerBase != base || lowerNS != ns {
		applied = append(applied, RuleNameCaseFold)
	}
	if foldedBase != lowerBase || foldedNS != lowerNS {
		applied = append(applied, RuleNameSeparatorFold)
	}

	return foldedNS, foldedBase, applied
}

// nameRulesForPair returns the normalization rules actually needed to make two names equal. This
// is what the report cites, so a name that was normalized but equal to another normalized name
// does not falsely claim a fold was required.
func nameRulesForPair(a, b string) []string {
	nsA, baseA := splitName(a)
	nsB, baseB := splitName(b)

	var rules []string
	if nsA != nsB || strings.HasPrefix(strings.TrimSpace(a), "@") != strings.HasPrefix(strings.TrimSpace(b), "@") {
		rules = append(rules, RuleNameNamespaceFold)
	}
	if baseA != baseB {
		switch {
		case strings.EqualFold(baseA, baseB):
			rules = append(rules, RuleNameCaseFold)
		case foldSeparators(strings.ToLower(baseA)) == foldSeparators(strings.ToLower(baseB)):
			rules = append(rules, RuleNameCaseFold, RuleNameSeparatorFold)
		default:
			rules = append(rules, RuleNameSeparatorFold)
		}
	}
	if len(rules) == 0 {
		rules = []string{RuleNameExact}
	}
	return sortedUnique(rules)
}

// NameRelation describes how two raw names relate after normalization.
type NameRelation struct {
	// Same is true when the names normalize to the same namespace and base name.
	Same bool
	// Rules are the normalization rules that had to be applied to make the names equal.
	Rules []string
}

// RelateNames reports whether two raw package names describe the same component name and which
// normalization rules made them equal. Type is not considered here; callers compare it separately.
func RelateNames(a, b string) NameRelation {
	aLower, aBase, aRules := normalizeName(a)
	bLower, bBase, bRules := normalizeName(b)

	if aLower != bLower || aBase != bBase {
		return NameRelation{Same: false}
	}

	rules := sortedUnique(append(aRules, bRules...))
	if len(rules) == 0 {
		rules = []string{RuleNameExact}
	}
	return NameRelation{Same: true, Rules: rules}
}

// VersionRelation describes how two versions relate.
type VersionRelation struct {
	// Same is true when the versions are equivalent (including a revision-only difference).
	Same bool
	// Class is the canonical version class both values belong to.
	Class string
	// Rule is the rule that established equivalence.
	Rule string
	// Conflict is true when the versions differ in a way that must be surfaced to a reviewer
	// (a package-manager revision), rather than a pure spelling difference.
	Conflict bool
}

// SemverEq reports whether two versions are the same semantic version. A leading "v" and missing
// patch/minor components are normalized by the semver parser, so `v1.2` and `1.2.0` are equal.
func SemverEq(a, b string) bool {
	av, err := semver.NewVersion(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	bv, err := semver.NewVersion(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	return av.Equal(bv)
}

// versionClass returns the class a single version belongs to for the given package type.
//
// For OS package types the class is the upstream version with the package-manager revision
// removed; for every other type a semver canonical form is used when both versions parse as
// semver, and otherwise the lower-cased literal version. Two records can only merge when their
// version classes are equal.
func versionClass(ty pkg.Type, version string) (class string, rule string) {
	v := strings.TrimSpace(version)
	if v == "" {
		return "", ""
	}

	if osTypes[ty] {
		if base := osVersionBase(v); base != "" {
			return base, RuleVersionExact
		}
	}

	if sv, err := semver.NewVersion(v); err == nil {
		return sv.String(), RuleVersionSemver
	}

	return strings.ToLower(v), RuleVersionExact
}

// osVersionBase strips a package-manager revision from an OS package version. The revision is the
// part after the final hyphen, per Debian policy; Alpine uses the same shape (`-r0`) and RPM puts
// its release there too. A tilde suffix marks a pre-release rather than a revision and is kept.
func osVersionBase(version string) string {
	v := stripEpoch(version)
	if i := strings.LastIndex(v, "-"); i > 0 {
		suffix := v[i+1:]
		if suffix != "" && !strings.HasPrefix(suffix, "~") {
			return v[:i]
		}
	}
	return v
}

// RelateVersions reports whether two raw versions belong to the same class for the given type.
func RelateVersions(ty pkg.Type, a, b string) VersionRelation {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return VersionRelation{}
	}

	if a == b {
		return VersionRelation{Same: true, Class: a, Rule: RuleVersionExact}
	}

	if osTypes[ty] {
		aClass, _ := versionClass(ty, a)
		bClass, _ := versionClass(ty, b)
		if aClass == bClass {
			if SemverEq(a, b) {
				return VersionRelation{Same: true, Class: aClass, Rule: RuleVersionSemver}
			}
			return VersionRelation{Same: true, Class: aClass, Rule: RuleVersionRevision, Conflict: true}
		}
		return VersionRelation{Class: aClass}
	}

	if SemverEq(a, b) {
		av, _ := semver.NewVersion(a)
		return VersionRelation{Same: true, Class: av.String(), Rule: RuleVersionSemver}
	}

	if strings.EqualFold(a, b) {
		return VersionRelation{Same: true, Class: strings.ToLower(a), Rule: RuleVersionExact}
	}

	aClass, _ := versionClass(ty, a)
	return VersionRelation{Class: aClass}
}

// versionRulesForPair returns the rules that made two records' versions equivalent.
func versionRulesForPair(a, b normalized) []string {
	rel := RelateVersions(a.record.Type, a.record.Version, b.record.Version)
	if rel.Same && rel.Rule != "" {
		return []string{rel.Rule}
	}
	if a.versionClass == b.versionClass && a.versionClass != "" {
		return []string{RuleVersionExact}
	}
	return nil
}

// sortedUnique returns the sorted, de-duplicated form of the input.
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
