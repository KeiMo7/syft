package trim

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/anchore/syft/syft/sbom"
)

// Report is the reproducible audit record attached at descriptor.configuration.trim.
type Report struct {
	Enabled              bool           `json:"enabled"`
	Complete             bool           `json:"complete"`
	BusinessLine         string         `json:"businessLine"`
	RuleSource           string         `json:"ruleSource"`
	RulesSource          string         `json:"rulesSource"`
	RulesDigest          string         `json:"rulesDigest"`
	RulesReloadedAtApply bool           `json:"rulesReloadedAtApply,omitempty"`
	Policy               Policy         `json:"policy"`
	BeforeCount          int            `json:"beforeCount"`
	AfterCount           int            `json:"afterCount"`
	RemovedCount         int            `json:"removedCount"`
	AttemptedRemoved     int            `json:"attemptedRemovedCount"`
	WouldRemoveCount     int            `json:"wouldRemoveCount,omitempty"`
	Fallback             bool           `json:"fallback,omitempty"`
	RelationshipsBefore  int            `json:"relationshipsBeforeCount"`
	RelationshipsAfter   int            `json:"relationshipsAfterCount"`
	RelationshipsRemoved int            `json:"relationshipsRemovedCount"`
	Unknown              UnknownStats   `json:"unknown"`
	ByCategory           map[string]int `json:"byCategory"`
	ByRule               map[string]int `json:"byRule"`
	AppliedRules         []string       `json:"appliedRules"`
	Warnings             []string       `json:"warnings,omitempty"`
}

// UnknownStats records components that were retained because the relevant signal was missing.
type UnknownStats struct {
	Total    int `json:"total"`
	Category int `json:"category"`
	Depth    int `json:"depth"`
}

// AggregateReport groups trim outcomes by business line for cross-image reporting.
type AggregateReport struct {
	BusinessLine         string         `json:"businessLine"`
	Reports              int            `json:"reports"`
	BeforeCount          int            `json:"beforeCount"`
	AfterCount           int            `json:"afterCount"`
	RemovedCount         int            `json:"removedCount"`
	RelationshipsRemoved int            `json:"relationshipsRemovedCount"`
	Unknown              UnknownStats   `json:"unknown"`
	ByCategory           map[string]int `json:"byCategory"`
	ByRule               map[string]int `json:"byRule"`
}

// AggregateRemovedByBusinessLine merges reports while counting each component only through the
// primary rule already recorded in its source report.
func AggregateRemovedByBusinessLine(reports []Report) []AggregateReport {
	aggregates := map[string]*AggregateReport{}
	for _, report := range reports {
		if !report.Enabled {
			continue
		}
		key := report.BusinessLine
		if key == "" {
			key = "default"
		}
		aggregate := aggregates[key]
		if aggregate == nil {
			aggregate = &AggregateReport{
				BusinessLine: key,
				ByCategory:   map[string]int{},
				ByRule:       map[string]int{},
			}
			aggregates[key] = aggregate
		}

		aggregate.Reports++
		aggregate.BeforeCount += report.BeforeCount
		aggregate.AfterCount += report.AfterCount
		aggregate.RemovedCount += report.RemovedCount
		aggregate.RelationshipsRemoved += report.RelationshipsRemoved
		aggregate.Unknown.Total += report.Unknown.Total
		aggregate.Unknown.Category += report.Unknown.Category
		aggregate.Unknown.Depth += report.Unknown.Depth
		for category, count := range report.ByCategory {
			aggregate.ByCategory[category] += count
		}
		for rule, count := range report.ByRule {
			aggregate.ByRule[rule] += count
		}
	}

	keys := make([]string, 0, len(aggregates))
	for key := range aggregates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]AggregateReport, 0, len(keys))
	for _, key := range keys {
		aggregate := aggregates[key]
		aggregate.ByCategory = sortedRuleMap(aggregate.ByCategory)
		aggregate.ByRule = sortedRuleMap(aggregate.ByRule)
		out = append(out, *aggregate)
	}
	return out
}

func (r *Report) addRemoved(category, rule string) {
	r.RemovedCount++
	r.AttemptedRemoved++
	if category != "" {
		r.ByCategory[category]++
	}
	r.ByRule[rule]++
}

func (r *Report) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

func attachReport(s *sbom.SBOM, report Report) error {
	configuration := map[string]any{}
	if s.Descriptor.Configuration != nil {
		payload, err := json.Marshal(s.Descriptor.Configuration)
		if err != nil {
			return fmt.Errorf("unable to encode existing SBOM configuration metadata: %w", err)
		}
		if err := json.Unmarshal(payload, &configuration); err != nil {
			return fmt.Errorf("unable to normalize existing SBOM configuration metadata: %w", err)
		}
	}
	configuration["trim"] = report
	s.Descriptor.Configuration = configuration
	return nil
}

func sortedRuleMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return map[string]int{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]int, len(values))
	for _, key := range keys {
		out[key] = values[key]
	}
	return out
}
