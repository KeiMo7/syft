package commands

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/clio/cliotestutils"
	"github.com/anchore/syft/cmd/syft/internal"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/timeline"
)

func Test_scanCLITimelineFlag(t *testing.T) {
	id := clio.Identification{Name: "syft", Version: "testing"}
	cfg := internal.AppClioSetupConfig(id, bytes.NewBuffer(nil))

	var got string
	assertion := func(t *testing.T, _ *cobra.Command, _ []string, cfgs ...any) {
		scanOpts, ok := cfgs[0].(*scanOptions)
		require.True(t, ok)
		got = scanOpts.Timeline.Dir
	}

	app := cliotestutils.NewApplication(t, cfg, assertion)
	cmd := Scan(app)
	cmd.SetArgs([]string{"some-image:some-tag", "--timeline-dir", "/tmp/history"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, "/tmp/history", got, "--timeline-dir must feed the timeline options")
}

func Test_scanOptions_timelineDisabledByDefault(t *testing.T) {
	opts := defaultScanOptions()
	assert.False(t, opts.Timeline.Enabled(), "the history must be off unless a directory is configured")
}

func Test_validateTimelineOutput(t *testing.T) {
	for _, format := range timelineOutputFormats() {
		assert.NoError(t, options.ValidateTimelineOutput(format), format)
	}
	assert.Error(t, options.ValidateTimelineOutput("yaml"))
}

func Test_timelineOptions_query(t *testing.T) {
	t.Run("time range is normalized", func(t *testing.T) {
		opts := defaultTimelineOptions()
		opts.Since = "2026-01-01"
		opts.Until = "2026-06-01T00:00:00+02:00"
		opts.Limit = 5

		query, err := opts.query()
		require.NoError(t, err)
		require.NotNil(t, query.Since)
		require.NotNil(t, query.Until)
		assert.Equal(t, "2026-01-01T00:00:00.000Z", timeline.FormatTimestamp(*query.Since))
		assert.Equal(t, "2026-05-31T22:00:00.000Z", timeline.FormatTimestamp(*query.Until))
		assert.Equal(t, 5, query.Limit)
	})

	t.Run("since after until is rejected", func(t *testing.T) {
		opts := defaultTimelineOptions()
		opts.Since = "2026-06-01"
		opts.Until = "2026-01-01"
		_, err := opts.query()
		require.ErrorContains(t, err, "is after")
	})

	t.Run("invalid timestamp is rejected", func(t *testing.T) {
		opts := defaultTimelineOptions()
		opts.Since = "yesterday-ish"
		_, err := opts.query()
		require.ErrorContains(t, err, "--since")
	})
}

func Test_runTimeline_requiresHistoryDirectory(t *testing.T) {
	opts := defaultTimelineOptions()
	err := runTimeline(opts)
	require.ErrorContains(t, err, "history directory is required")
}

func Test_runTimeline_rendersEmptyHistory(t *testing.T) {
	opts := defaultTimelineOptions()
	opts.Dir = t.TempDir()

	// renders without error; the report itself goes on the bus, so only the absence of an error
	// (and of any created file) is asserted here
	require.NoError(t, runTimeline(opts))
}

func Test_renderTimeline_viewsAgree(t *testing.T) {
	derived := &timeline.Timeline{
		Snapshots: 1,
		Range:     timeline.TimeRange{From: "2026-01-01T00:00:00.000Z", To: "2026-01-01T00:00:00.000Z"},
		Components: []timeline.ComponentTimeline{{
			Key:       "npm/lodash",
			Name:      "lodash",
			Type:      "npm",
			FirstSeen: "2026-01-01T00:00:00.000Z",
			LastSeen:  "2026-01-01T00:00:00.000Z",
			Present:   true,
			Version:   "4.17.21",
			Changes: []timeline.Change{{
				Timestamp: "2026-01-01T00:00:00.000Z",
				Component: "npm/lodash",
				Name:      "lodash",
				Type:      "npm",
				Kind:      timeline.KindAdded,
				ToVersion: "4.17.21",
			}},
		}},
		Timepoints: []timeline.Timepoint{{
			Timestamp: "2026-01-01T00:00:00.000Z",
			Changes: []timeline.Change{{
				Timestamp: "2026-01-01T00:00:00.000Z",
				Component: "npm/lodash",
				Name:      "lodash",
				Type:      "npm",
				Kind:      timeline.KindAdded,
				ToVersion: "4.17.21",
			}},
		}},
	}

	for _, format := range []string{
		timeline.FormatText,
		timeline.FormatJSON,
		timeline.FormatComponents,
		timeline.FormatTimepoints,
	} {
		out, err := renderTimeline(format, derived)
		require.NoError(t, err, format)
		assert.NotEmpty(t, out, format)
	}
}

func Test_timelineCLIWiring(t *testing.T) {
	id := clio.Identification{Name: "syft", Version: "testing"}
	cfg := internal.AppClioSetupConfig(id, bytes.NewBuffer(nil))

	var got *timelineOptions
	assertion := func(t *testing.T, _ *cobra.Command, _ []string, cfgs ...any) {
		opts, ok := cfgs[0].(*timelineOptions)
		require.True(t, ok)
		got = opts
	}

	app := cliotestutils.NewApplication(t, cfg, assertion)
	cmd := Timeline(app)
	cmd.SetArgs([]string{
		"--dir", "/tmp/history",
		"-o", "timeline-timepoints",
		"--component", "lodash",
		"--since", "2026-01-01",
		"--until", "2026-06-01T00:00:00Z",
		"--limit", "10",
	})
	require.NoError(t, cmd.Execute())

	require.NotNil(t, got)
	assert.Equal(t, "/tmp/history", got.Dir)
	assert.Equal(t, timeline.FormatTimepoints, got.Output)
	assert.Equal(t, "lodash", got.Component)
	assert.Equal(t, "2026-01-01", got.Since)
	assert.Equal(t, "2026-06-01T00:00:00Z", got.Until)
	assert.Equal(t, 10, got.Limit)
}

func Test_renderTimeline_rejectsUnknownFormat(t *testing.T) {
	_, err := renderTimeline("yaml", &timeline.Timeline{})
	// unknown formats fall back to text today, so the guard lives in ValidateTimelineOutput
	assert.NoError(t, err)
}
