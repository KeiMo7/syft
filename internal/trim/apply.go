package trim

import (
	"fmt"
	"sort"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type selection struct {
	policy  Policy
	name    string
	source  string
	warning string
}

// Apply returns a trimmed copy of the SBOM and an audit report. It never mutates the input
// package collection, relationships, or component model.
func Apply(input sbom.SBOM, config *Config) (sbom.SBOM, Report, error) {
	snapshot, err := config.snapshot()
	if err != nil {
		return sbom.SBOM{}, Report{}, err
	}
	if !snapshot.Enabled {
		return input, Report{Enabled: false}, nil
	}

	selected, err := selectPolicy(snapshot, input.Source)
	if err != nil {
		return sbom.SBOM{}, Report{}, err
	}

	packages := input.Artifacts.Packages.Sorted()
	report := Report{
		Enabled:              true,
		Complete:             true,
		BusinessLine:         selected.name,
		RuleSource:           selected.source,
		RulesSource:          snapshot.RulesSource,
		RulesDigest:          snapshot.RulesDigest,
		RulesReloadedAtApply: snapshot.ReloadedAtApply,
		Policy:               selected.policy,
		BeforeCount:          len(packages),
		RelationshipsBefore:  len(input.Relationships),
		ByCategory:           map[string]int{},
		ByRule:               map[string]int{},
	}
	if selected.warning != "" {
		report.warn("%s", selected.warning)
	}

	effectivePolicy := normalizePolicy(selected.policy)
	report.Policy = effectivePolicy
	report.AppliedRules = appliedRules(effectivePolicy)

	depths := analyzeDepth(packages, input.Relationships)
	retainedIDs := make(map[artifact.ID]struct{}, len(packages))
	unknownIDs := make(map[artifact.ID]struct{})
	categoryUnknownIDs := make(map[artifact.ID]struct{})
	depthUnknownIDs := make(map[artifact.ID]struct{})

	for _, p := range packages {
		signals := inspectPackage(p, effectivePolicy)

		category := firstEnabledCategory(signals.categories, effectivePolicy.Categories)
		if len(signals.categories) == 0 && hasEnabledCategory(effectivePolicy.Categories) {
			categoryUnknownIDs[p.ID()] = struct{}{}
			unknownIDs[p.ID()] = struct{}{}
		}

		locationExcluded := pathExcluded(p, effectivePolicy.ExcludePaths)
		_, graphTransitive := depths.transitive[p.ID()]
		depthTransitive := signals.depth == "transitive" || (signals.depth == "" && graphTransitive)
		if signals.depth == "" {
			if _, unknown := depths.unknown[p.ID()]; unknown && effectivePolicy.DirectOnly {
				depthUnknownIDs[p.ID()] = struct{}{}
				unknownIDs[p.ID()] = struct{}{}
			}
		}

		removed := ""
		removedCategory := ""
		switch {
		case category != "":
			removed = "category:" + category
			removedCategory = category
		case locationExcluded:
			removed = "location:excluded-path"
		case effectivePolicy.DirectOnly && depthTransitive:
			removed = "depth:transitive"
		}

		if removed == "" {
			retainedIDs[p.ID()] = struct{}{}
			continue
		}
		report.addRemoved(removedCategory, removed)
	}

	report.Unknown = UnknownStats{
		Total:    len(unknownIDs),
		Category: len(categoryUnknownIDs),
		Depth:    len(depthUnknownIDs),
	}

	if len(retainedIDs) == 0 && len(packages) > 0 {
		report.Fallback = true
		report.WouldRemoveCount = report.RemovedCount
		report.RemovedCount = 0
		report.AfterCount = len(packages)
		retainedIDs = make(map[artifact.ID]struct{}, len(packages))
		for _, p := range packages {
			retainedIDs[p.ID()] = struct{}{}
		}
		report.warn("all %d components matched trim rules; retaining the original component list instead of emitting an empty SBOM", report.WouldRemoveCount)
	} else {
		report.AfterCount = len(retainedIDs)
	}

	report.ByRule = sortedRuleMap(report.ByRule)
	report.ByCategory = sortedRuleMap(report.ByCategory)

	out := cloneSBOM(input, packages, retainedIDs)
	report.RelationshipsAfter = len(out.Relationships)
	report.RelationshipsRemoved = report.RelationshipsBefore - report.RelationshipsAfter

	if err := attachReport(&out, report); err != nil {
		return sbom.SBOM{}, Report{}, err
	}
	return out, report, nil
}

func selectPolicy(snapshot configSnapshot, description source.Description) (selection, error) {
	if snapshot.BusinessLine != "" {
		for _, rule := range snapshot.BusinessLines {
			if rule.Name == snapshot.BusinessLine {
				return selection{
					policy: rule.Policy,
					name:   rule.Name,
					source: "explicit-business-line",
				}, nil
			}
		}
		return selection{}, fmt.Errorf("configured trim business line %q was not found", snapshot.BusinessLine)
	}

	if len(snapshot.BusinessLines) > 0 {
		for _, rule := range snapshot.BusinessLines {
			if matchesImagePatterns(rule.Images, description) {
				return selection{
					policy: rule.Policy,
					name:   rule.Name,
					source: "business-line-image-match",
				}, nil
			}
		}
		return selection{
			policy: snapshot.Default,
			name:   "default",
			source: "default-no-business-line-match",
			warning: fmt.Sprintf(
				"source %q did not match any trim business line; using default rules",
				description.Name,
			),
		}, nil
	}

	return selection{
		policy: snapshot.Default,
		name:   "default",
		source: "default",
	}, nil
}

func normalizePolicy(policy Policy) Policy {
	out := clonePolicy(policy)
	if out.ExcludePaths == nil {
		out.ExcludePaths = append([]string(nil), DefaultExcludePaths...)
	}
	return out
}

func appliedRules(policy Policy) []string {
	var rules []string
	for _, category := range ValidCategories {
		if policy.Categories[category] {
			rules = append(rules, "category:"+category)
		}
	}
	if len(policy.ExcludePaths) > 0 {
		rules = append(rules, "location:excluded-path")
	}
	if policy.DirectOnly {
		rules = append(rules, "depth:transitive")
	}
	sort.Strings(rules)
	return rules
}

func firstEnabledCategory(categories []string, enabled map[string]bool) string {
	for _, category := range ValidCategories {
		if !enabled[category] {
			continue
		}
		for _, found := range categories {
			if found == category {
				return category
			}
		}
	}
	return ""
}

func hasEnabledCategory(enabled map[string]bool) bool {
	for _, category := range ValidCategories {
		if enabled[category] {
			return true
		}
	}
	return false
}

func cloneSBOM(input sbom.SBOM, packages []pkg.Package, retained map[artifact.ID]struct{}) sbom.SBOM {
	out := input
	out.Artifacts = input.Artifacts
	out.Artifacts.Packages = pkg.NewCollection()

	for _, p := range packages {
		if _, ok := retained[p.ID()]; ok {
			out.Artifacts.Packages.Add(p)
		}
	}

	out.Relationships = make([]artifact.Relationship, 0, len(input.Relationships))
	for _, relationship := range input.Relationships {
		if relationshipReferencesRemovedPackage(relationship, retained) {
			continue
		}
		out.Relationships = append(out.Relationships, relationship)
	}
	out.Relationships = out.RelationshipsSorted()

	return out
}

func relationshipReferencesRemovedPackage(relationship artifact.Relationship, retained map[artifact.ID]struct{}) bool {
	if p, ok := asPackage(relationship.From); ok {
		if _, exists := retained[p.ID()]; !exists {
			return true
		}
	}
	if p, ok := asPackage(relationship.To); ok {
		if _, exists := retained[p.ID()]; !exists {
			return true
		}
	}
	return false
}
