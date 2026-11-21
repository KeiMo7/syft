package commands

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/timeline"
)

const timelineExample = `  {{.appName}} {{.command}} --dir ./history                                       show the recorded history for every component
  {{.appName}} {{.command}} --dir ./history --component lodash                   show one component's first appearance and changes
  {{.appName}} {{.command}} --dir ./history --since 2026-01-01 --until 2026-06-01 what changed in the first half of the year
  {{.appName}} {{.command}} --dir ./history -o timeline-timepoints                what was added and removed at each point in time
  {{.appName}} {{.command}} --dir ./history --import old-2026-01-01.syft.json     backfill a historical SBOM
`

// template keys used by the command example
const (
	appNameTemplateKey = "appName"
	commandTemplateKey = "command"
)

// timelineOptions are the options specific to the timeline command. The history location and the
// report shape live under the shared `timeline` configuration section, so a scan and the timeline
// command read the same settings.
type timelineOptions struct {
	options.Config   `yaml:",inline" mapstructure:",squash"`
	options.Timeline `yaml:"timeline" json:"timeline" mapstructure:"timeline"`

	Component string   `yaml:"component" json:"component" mapstructure:"component"`
	Since     string   `yaml:"since" json:"since" mapstructure:"since"`
	Until     string   `yaml:"until" json:"until" mapstructure:"until"`
	Limit     int      `yaml:"limit" json:"limit" mapstructure:"limit"`
	Import    []string `yaml:"import" json:"import" mapstructure:"import"`
	ImportAt  string   `yaml:"import-at" json:"import-at" mapstructure:"import-at"`
}

func (o *timelineOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Dir, "dir", "",
		"directory holding the append-only history of SBOM generations")
	flags.StringVarP(&o.Output, "output", "o",
		"timeline report format: "+strings.Join(timelineOutputFormats(), ", "))
	flags.StringVarP(&o.Component, "component", "",
		"restrict the timeline to one component (identity key, name, <type>/<name>, or purl)")
	flags.StringVarP(&o.Since, "since", "",
		"only report changes at or after this time (UTC RFC3339 or a date, e.g. 2026-01-01)")
	flags.StringVarP(&o.Until, "until", "",
		"only report changes at or before this time (UTC RFC3339 or a date, e.g. 2026-06-01)")
	flags.IntVarP(&o.Limit, "limit", "",
		"maximum number of changes to report (0 means no limit)")
	flags.StringArrayVarP(&o.Import, "import", "",
		"backfill history from an SBOM document (repeatable; any syft-supported format)")
	flags.StringVarP(&o.ImportAt, "import-at", "",
		"timestamp to record for the imported documents (defaults to each file's modification time)")
}

func (o *timelineOptions) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Component, "restrict the timeline to one component")
	descriptions.Add(&o.Since, "only report changes at or after this time")
	descriptions.Add(&o.Until, "only report changes at or before this time")
	descriptions.Add(&o.Limit, "maximum number of changes to report (0 means no limit)")
	descriptions.Add(&o.Import, "backfill history from SBOM documents")
	descriptions.Add(&o.ImportAt, "timestamp to record for imported documents")
}

func defaultTimelineOptions() *timelineOptions {
	return &timelineOptions{
		Timeline: options.DefaultTimeline(),
	}
}

func timelineOutputFormats() []string {
	formats := []string{
		timeline.FormatText,
		timeline.FormatJSON,
		timeline.FormatComponents,
		timeline.FormatTimepoints,
	}
	sort.Strings(formats)
	return formats
}

// Timeline constructs the `syft timeline` command.
func Timeline(app clio.Application) *cobra.Command {
	id := app.ID()
	opts := defaultTimelineOptions()

	return app.SetupCommand(&cobra.Command{
		Use:   "timeline [OPTIONS]",
		Short: "Show, query, and backfill the SBOM history timeline",
		Long: "[Experimental] Report when each component first appeared, when it disappeared, and when its version or " +
			"source changed, using the append-only history recorded by `syft scan --timeline-dir`.",
		Example: internal.Tprintf(timelineExample, map[string]any{
			appNameTemplateKey: id.Name,
			commandTemplateKey: "timeline",
		}),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return runTimeline(opts)
		},
	}, opts)
}

func runTimeline(opts *timelineOptions) error {
	if !opts.Enabled() {
		return fmt.Errorf("a history directory is required (use --dir or the timeline.dir configuration)")
	}
	if err := options.ValidateTimelineOutput(opts.Output); err != nil {
		return err
	}

	store := timeline.Open(opts.Dir)

	if len(opts.Import) > 0 {
		if err := importDocuments(store, opts.Import, opts.ImportAt); err != nil {
			return err
		}
	}

	query, err := opts.query()
	if err != nil {
		return err
	}

	derived, err := store.Read(query)
	if err != nil {
		return fmt.Errorf("unable to read the history in %q: %w", opts.Dir, err)
	}

	report, err := renderTimeline(opts.Output, derived)
	if err != nil {
		return err
	}

	// reports are published on the bus like every other command, which writes them to stdout and
	// keeps them available to the UI layer
	bus.Report(report)
	return nil
}

func (o *timelineOptions) query() (timeline.Query, error) {
	query := timeline.Query{
		Component: o.Component,
		Limit:     o.Limit,
	}

	if o.Since != "" {
		since, err := timeline.ParseTimestamp(o.Since)
		if err != nil {
			return query, fmt.Errorf("invalid --since value: %w", err)
		}
		query.Since = &since
	}
	if o.Until != "" {
		until, err := timeline.ParseTimestamp(o.Until)
		if err != nil {
			return query, fmt.Errorf("invalid --until value: %w", err)
		}
		query.Until = &until
	}
	if query.Since != nil && query.Until != nil && query.Since.After(*query.Until) {
		return query, fmt.Errorf("--since (%s) is after --until (%s)", o.Since, o.Until)
	}

	return query, nil
}

func importDocuments(store *timeline.Store, paths []string, importAt string) error {
	var explicit time.Time
	if importAt != "" {
		parsed, err := timeline.ParseTimestamp(importAt)
		if err != nil {
			return fmt.Errorf("invalid --import-at value: %w", err)
		}
		explicit = parsed
	}

	var errs error
	for _, path := range paths {
		at := explicit
		if at.IsZero() {
			at = timeline.ImportTime(path)
		}

		rec, added, err := store.ImportFile(path, at)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("unable to import %q: %w", path, err))
			continue
		}

		if added {
			log.Infof("imported %s as snapshot %s (%s)", filepath.Base(path), rec.SnapshotID, rec.Timestamp)
		} else {
			log.Debugf("%s is already recorded as %s", path, rec.SnapshotID)
		}
	}
	return errs
}

func renderTimeline(output string, derived *timeline.Timeline) (string, error) {
	buf := &strings.Builder{}
	var err error
	switch output {
	case timeline.FormatJSON:
		err = timeline.RenderJSON(buf, derived)
	case timeline.FormatComponents:
		err = timeline.RenderComponents(buf, derived)
	case timeline.FormatTimepoints:
		err = timeline.RenderTimepoints(buf, derived)
	default:
		err = timeline.RenderText(buf, derived)
	}
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
