package diff

import "github.com/anchore/syft/syft/pkg"

// ReportVersion is the schema of the machine-readable diff report itself; bump it when
// the JSON shape changes in a breaking way.
const ReportVersion = "1.0.0"

// InputDescription preserves the provenance of one side of the diff for audit purposes.
type InputDescription struct {
	// Path is the file path the SBOM was read from ("-" when read from STDIN).
	Path string `json:"path"`

	// FormatID is the detected SBOM format (e.g. syft-json, spdx-json, cyclonedx-json).
	FormatID string `json:"format"`

	// SchemaVersion is the schema version declared by the SBOM document.
	SchemaVersion string `json:"schemaVersion"`

	// SourceType is the cataloged source type (e.g. image, directory, file), when known.
	SourceType string `json:"sourceType,omitempty"`

	// SourceName is the cataloged source name (image name, directory path, ...).
	SourceName string `json:"sourceName,omitempty"`

	// SourceVersion is the cataloged source version (e.g. image tag).
	SourceVersion string `json:"sourceVersion,omitempty"`

	// GeneratedAt records when the input SBOM was generated. It is taken from the document
	// metadata when available, otherwise from the input file's modification time, and is
	// nil when neither is known.
	GeneratedAt *string `json:"generatedAt,omitempty"`

	// ComponentCount is the number of components in the input after path-scope filtering.
	ComponentCount int `json:"componentCount"`
}

// GroupCount is the number of changes sharing a grouping dimension.
type GroupCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Counts summarizes the diff across categories and grouping dimensions.
type Counts struct {
	Added          int          `json:"added"`
	Removed        int          `json:"removed"`
	VersionChanged int          `json:"versionChanged"`
	VersionUnknown int          `json:"versionUnknown"`
	HighRisk       int          `json:"highRisk"`
	ByType         []GroupCount `json:"byType"`
	ByLayer        []GroupCount `json:"byLayer"`
	ByDirection    []GroupCount `json:"byDirection"`
}

// Report is the full, machine-readable diff result.
type Report struct {
	// ReportSchema is the version of this report structure.
	ReportSchema string `json:"reportSchema"`

	// Old and New describe the two compared inputs.
	Old InputDescription `json:"old"`
	New InputDescription `json:"new"`

	// SourceMismatch is true when the two inputs catalog different source types
	// (for example an image versus a directory).
	SourceMismatch bool `json:"sourceMismatch"`

	// PathScope holds the path prefixes the diff was limited to, when any.
	PathScope []string `json:"pathScope,omitempty"`

	// HighRiskOnly records whether the report was restricted to high-risk changes.
	HighRiskOnly bool `json:"highRiskOnly"`

	// Counts summarizes Changes.
	Counts Counts `json:"counts"`

	// Changes is the (optionally paginated) list of component changes.
	Changes []Change `json:"changes"`

	// TotalChanges is the total number of changes before pagination.
	TotalChanges int `json:"totalChanges"`

	// Page and PageSize describe the pagination applied to Changes; PageSize of 0
	// means no pagination.
	Page     int `json:"page,omitempty"`
	PageSize int `json:"pageSize,omitempty"`
}

// NewReport builds a Report from computed changes and input descriptions.
func NewReport(oldInput, newInput InputDescription, changes []Change, opts Options) Report {
	if changes == nil {
		changes = []Change{}
	}

	report := Report{
		ReportSchema:   ReportVersion,
		Old:            oldInput,
		New:            newInput,
		SourceMismatch: sourceMismatch(oldInput, newInput),
		HighRiskOnly:   opts.HighRiskOnly,
		Changes:        changes,
		TotalChanges:   len(changes),
	}

	if len(opts.PathPrefixes) > 0 {
		report.PathScope = append(report.PathScope, opts.PathPrefixes...)
	}

	report.Counts = countChanges(changes)

	return report
}

func sourceMismatch(oldInput, newInput InputDescription) bool {
	if oldInput.SourceType == "" || newInput.SourceType == "" {
		return false
	}
	return oldInput.SourceType != newInput.SourceType
}

func countChanges(changes []Change) Counts {
	var counts Counts

	typeGroups := make(map[string]int)
	layerGroups := make(map[string]int)
	directionGroups := make(map[string]int)

	for _, change := range changes {
		switch change.Type {
		case Added:
			counts.Added++
		case Removed:
			counts.Removed++
		case VersionChanged:
			counts.VersionChanged++
		case VersionUnknown:
			counts.VersionUnknown++
		}

		if change.IsHighRisk() {
			counts.HighRisk++
		}

		typeKey := string(change.ComponentType)
		if typeKey == "" {
			typeKey = string(pkg.UnknownPkg)
		}
		typeGroups[typeKey]++

		layerKey := layerGroupKey(change)
		layerGroups[layerKey]++

		if change.Direction != "" {
			directionGroups[string(change.Direction)]++
		}
	}

	counts.ByType = sortedGroupCounts(typeGroups)
	counts.ByLayer = sortedGroupCounts(layerGroups)
	counts.ByDirection = sortedGroupCounts(directionGroups)

	return counts
}

// layerGroupKey reports the layer a change belongs to, preferring the new side and
// falling back to the old side so added/removed components still group sensibly.
func layerGroupKey(change Change) string {
	switch {
	case change.NewLayer != "":
		return string(change.NewLayer)
	case change.OldLayer != "":
		return string(change.OldLayer)
	default:
		return string(UnknownLayer)
	}
}

func sortedGroupCounts(groups map[string]int) []GroupCount {
	out := make([]GroupCount, 0, len(groups))
	for key, count := range groups {
		out = append(out, GroupCount{Key: key, Count: count})
	}

	sortGroupCounts(out)

	return out
}

func sortGroupCounts(groups []GroupCount) {
	for i := 1; i < len(groups); i++ {
		for j := i; j > 0 && groups[j-1].Key > groups[j].Key; j-- {
			groups[j-1], groups[j] = groups[j], groups[j-1]
		}
	}
}
