package timeline

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Report formats accepted by the timeline command.
const (
	FormatText       = "timeline-text"
	FormatJSON       = "timeline-json"
	FormatComponents = "timeline-components"
	FormatTimepoints = "timeline-timepoints"
)

// RenderJSON writes the full derived timeline as indented JSON.
func RenderJSON(w io.Writer, timeline *Timeline) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(timeline); err != nil {
		return fmt.Errorf("unable to encode timeline: %w", err)
	}
	return nil
}

// RenderComponents writes the per-component view.
func RenderComponents(w io.Writer, timeline *Timeline) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	doc := struct {
		Snapshots  int                 `json:"snapshots"`
		Range      TimeRange           `json:"range"`
		Components []ComponentTimeline `json:"components"`
		Problems   []Problem           `json:"problems,omitempty"`
		Truncated  bool                `json:"truncated,omitempty"`
	}{
		Snapshots:  timeline.Snapshots,
		Range:      timeline.Range,
		Components: timeline.Components,
		Problems:   timeline.Problems,
		Truncated:  timeline.Truncated,
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("unable to encode component timeline: %w", err)
	}
	return nil
}

// RenderTimepoints writes the per-timestamp view.
func RenderTimepoints(w io.Writer, timeline *Timeline) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	doc := struct {
		Snapshots  int         `json:"snapshots"`
		Range      TimeRange   `json:"range"`
		Timepoints []Timepoint `json:"timepoints"`
		Problems   []Problem   `json:"problems,omitempty"`
		Truncated  bool        `json:"truncated,omitempty"`
	}{
		Snapshots:  timeline.Snapshots,
		Range:      timeline.Range,
		Timepoints: timeline.Timepoints,
		Problems:   timeline.Problems,
		Truncated:  timeline.Truncated,
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("unable to encode timepoint timeline: %w", err)
	}
	return nil
}

// RenderText writes a compact, human-readable summary of the per-component view.
func RenderText(w io.Writer, timeline *Timeline) error {
	var sb strings.Builder

	if timeline.Snapshots == 0 {
		sb.WriteString("no snapshots recorded\n")
		_, err := io.WriteString(w, sb.String())
		return err
	}

	fmt.Fprintf(&sb, "history: %d snapshot(s), %s .. %s\n", timeline.Snapshots, timeline.Range.From, timeline.Range.To)
	fmt.Fprintf(&sb, "components: %d\n", len(timeline.Components))

	for _, c := range timeline.Components {
		fmt.Fprintf(&sb, "\n%s (%s)\n", c.Name, c.Key)
		fmt.Fprintf(&sb, "  first seen: %s\n", c.FirstSeen)
		if c.Present {
			fmt.Fprintf(&sb, "  last seen:  %s (present)\n", c.LastSeen)
			fmt.Fprintf(&sb, "  current:    %s", valueOrUnknown(c.Version))
			if c.Source != "" {
				fmt.Fprintf(&sb, " from %s", c.Source)
			}
			sb.WriteString("\n")
		} else {
			fmt.Fprintf(&sb, "  removed at: %s\n", c.RemovedAt)
		}
		for _, change := range c.Changes {
			fmt.Fprintf(&sb, "  %s  %s\n", change.Timestamp, describeChange(change))
		}
	}

	if len(timeline.Problems) > 0 {
		sb.WriteString("\nproblems:\n")
		for _, problem := range timeline.Problems {
			fmt.Fprintf(&sb, "  [%s] %s\n    impact: %s\n", problem.Kind, problem.Message, problem.Impact)
		}
	}

	if timeline.Truncated {
		sb.WriteString("\n(output truncated by the requested limit)\n")
	}

	_, err := io.WriteString(w, sb.String())
	return err
}

func describeChange(change Change) string {
	switch change.Kind {
	case KindAdded:
		return "added at " + valueOrUnknown(change.ToVersion) + sourceSuffix(change.ToSource)
	case KindRemoved:
		return "removed (was " + valueOrUnknown(change.FromVersion) + ")"
	case KindChanged:
		var changes []string
		if change.FromVersion != change.ToVersion {
			changes = append(changes, valueOrUnknown(change.FromVersion)+" -> "+valueOrUnknown(change.ToVersion))
		}
		if change.FromSource != change.ToSource {
			changes = append(changes, "source "+valueOrUnknown(change.FromSource)+" -> "+valueOrUnknown(change.ToSource))
		}
		return "changed: " + strings.Join(changes, ", ")
	}
	return string(change.Kind)
}

func sourceSuffix(source string) string {
	if source == "" {
		return ""
	}
	return " from " + source
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "(unknown)"
	}
	return value
}
