package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/clio"
)

var _ clio.FieldDescriber = (*Timeline)(nil)

// Timeline controls the optional, append-only history of SBOM generations.
//
// The history is fully opt-in: when Dir is empty no history file is created and a scan behaves
// exactly as it did before this option existed.
type Timeline struct {
	// Dir is the directory holding the history journal. It is created on the first write.
	Dir string `yaml:"dir" json:"dir" mapstructure:"dir"`

	// Output selects the report shape for the timeline command.
	Output string `yaml:"output" json:"output" mapstructure:"output"`
}

// Timeline output formats.
const (
	TimelineOutputText       = "timeline-text"
	TimelineOutputJSON       = "timeline-json"
	TimelineOutputComponents = "timeline-components"
	TimelineOutputTimepoints = "timeline-timepoints"
)

func DefaultTimeline() Timeline {
	return Timeline{
		Output: TimelineOutputText,
	}
}

func (o *Timeline) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Dir, `directory holding the append-only history of SBOM generations

when unset, no history is recorded and no extra files are produced`)
	descriptions.Add(&o.Output, fmt.Sprintf(`report shape for the timeline command (options: %s)`, strings.Join(timelineOutputFormats(), ", ")))
}

// Enabled reports whether history recording was requested.
func (o Timeline) Enabled() bool {
	return strings.TrimSpace(o.Dir) != ""
}

func timelineOutputFormats() []string {
	formats := []string{
		TimelineOutputText,
		TimelineOutputJSON,
		TimelineOutputComponents,
		TimelineOutputTimepoints,
	}
	sort.Strings(formats)
	return formats
}

// ValidateTimelineOutput checks a requested timeline report shape.
func ValidateTimelineOutput(output string) error {
	for _, format := range timelineOutputFormats() {
		if output == format {
			return nil
		}
	}
	return fmt.Errorf("unsupported timeline output %q, supported formats are: %s", output, strings.Join(timelineOutputFormats(), ", "))
}
