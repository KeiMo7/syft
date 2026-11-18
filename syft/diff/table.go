package diff

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// WriteTable writes a human-readable diff grouped first by change type and then by
// component type and dependency layer, matching the grouping dimensions used in the
// machine-readable report.
func WriteTable(writer io.Writer, report Report) error {
	var builder strings.Builder

	fmt.Fprintf(&builder, "SBOM diff report (schema %s)\n", report.ReportSchema)
	fmt.Fprintf(&builder, "old: %s (%s/%s", report.Old.Path, report.Old.FormatID, report.Old.SchemaVersion)
	if report.Old.SourceType != "" {
		fmt.Fprintf(&builder, ", source=%s", report.Old.SourceType)
	}
	builder.WriteString(")\n")
	fmt.Fprintf(&builder, "new: %s (%s/%s", report.New.Path, report.New.FormatID, report.New.SchemaVersion)
	if report.New.SourceType != "" {
		fmt.Fprintf(&builder, ", source=%s", report.New.SourceType)
	}
	builder.WriteString(")\n")

	if report.SourceMismatch {
		fmt.Fprintf(&builder, "WARNING: source types differ (old=%s new=%s); component locations are not directly comparable\n",
			report.Old.SourceType, report.New.SourceType)
	}

	if len(report.PathScope) > 0 {
		fmt.Fprintf(&builder, "path scope: %s\n", strings.Join(report.PathScope, ", "))
	}

	if report.HighRiskOnly {
		builder.WriteString("filter: high-risk changes only\n")
	}

	fmt.Fprintf(&builder, "summary: added=%d removed=%d version-changed=%d version-unknown=%d high-risk=%d (total=%d)\n",
		report.Counts.Added, report.Counts.Removed, report.Counts.VersionChanged,
		report.Counts.VersionUnknown, report.Counts.HighRisk, report.TotalChanges)

	if report.TotalChanges != len(report.Changes) {
		fmt.Fprintf(&builder, "showing %d of %d changes (page=%d pageSize=%d)\n",
			len(report.Changes), report.TotalChanges, report.Page, report.PageSize)
	}

	builder.WriteByte('\n')

	sections := []struct {
		title string
		types []ChangeType
	}{
		{"Added components", []ChangeType{Added}},
		{"Removed components", []ChangeType{Removed}},
		{"Version changes", []ChangeType{VersionChanged, VersionUnknown}},
	}

	for _, section := range sections {
		sectionChanges := filterByTypes(report.Changes, section.types)
		if len(sectionChanges) == 0 {
			continue
		}

		fmt.Fprintf(&builder, "%s (%d):\n", section.title, len(sectionChanges))
		writeGroupedTable(&builder, sectionChanges)
		builder.WriteByte('\n')
	}

	if len(report.Changes) == 0 {
		builder.WriteString("no component changes detected\n")
	}

	tabbed := tabwriter.NewWriter(writer, 0, 2, 2, ' ', 0)
	if _, err := io.WriteString(tabbed, builder.String()); err != nil {
		return err
	}
	return tabbed.Flush()
}

func filterByTypes(changes []Change, wanted []ChangeType) []Change {
	var out []Change
	for _, change := range changes {
		for _, changeType := range wanted {
			if change.Type == changeType {
				out = append(out, change)
				break
			}
		}
	}
	return out
}

func writeGroupedTable(builder *strings.Builder, changes []Change) {
	groups := make(map[string][]Change)
	var groupOrder []string

	for _, change := range changes {
		groupKey := fmt.Sprintf("%s / %s", change.ComponentType, layerGroupKey(change))
		if _, ok := groups[groupKey]; !ok {
			groupOrder = append(groupOrder, groupKey)
		}
		groups[groupKey] = append(groups[groupKey], change)
	}

	sort.Strings(groupOrder)

	for _, groupKey := range groupOrder {
		groupChanges := groups[groupKey]
		fmt.Fprintf(builder, "  [%s]\n", groupKey)
		fmt.Fprintf(builder, "    %s\t%s\t%s\t%s\t%s\n", "NAME", "OLD", "NEW", "DETAIL", "FLAGS")

		for _, change := range groupChanges {
			fmt.Fprintf(builder, "    %s\t%s\t%s\t%s\t%s\n",
				change.Name,
				dashWhenEmpty(change.OldVersion),
				dashWhenEmpty(change.NewVersion),
				changeDetail(change),
				changeFlags(change),
			)
		}
	}
}

func changeDetail(change Change) string {
	switch change.Type {
	case VersionChanged:
		return string(change.Direction)
	case VersionUnknown:
		return "version-unknown"
	default:
		return string(change.Type)
	}
}

func changeFlags(change Change) string {
	var flags []string
	if change.HighRisk {
		flags = append(flags, "high-risk")
	}
	if change.Unreliable {
		flags = append(flags, "unreliable("+string(change.IdentityRule)+")")
	}
	if change.LayerChanged {
		flags = append(flags, "layer:"+string(change.OldLayer)+"->"+string(change.NewLayer))
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ",")
}

func dashWhenEmpty(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
