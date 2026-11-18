package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

func progressEvent() partybus.Event {
	return partybus.Event{
		Type: event.CatalogingProgress,
		Value: monitor.CatalogingProgress{
			Event:     monitor.CatalogingProgressEvent,
			Sequence:  1,
			Expected:  2,
			Remaining: 1,
			InFlight:  1,
			Stages: []monitor.CatalogingStage{{
				Stage:     "python-package-cataloger",
				Count:     5,
				ElapsedMS: 25,
				Elapsed:   "25ms",
				Failed:    false,
				State:     "completed",
				Layer:     2,
				Parser:    "python",
			}},
			Details: []monitor.CatalogingStage{{
				Stage:     "python-package-cataloger",
				Count:     5,
				ElapsedMS: 25,
				Elapsed:   "25ms",
				Failed:    false,
				State:     "completed",
				Layer:     2,
				Parser:    "python",
			}},
		},
	}
}

func TestProgressWriter_redirectedOutputKeepsStableFields(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "progress-*.jsonl")
	require.NoError(t, err)

	writer := newProgressWriter(f)
	writer.WriteEvent(progressEvent())
	require.NoError(t, f.Close())

	content, err := os.ReadFile(f.Name())
	require.NoError(t, err)

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	require.Len(t, lines, 1)

	var document map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &document))
	assert.Equal(t, monitor.CatalogingProgressEvent, document["event"])

	for _, section := range []string{"stages", "details"} {
		rows, ok := document[section].([]any)
		require.True(t, ok)
		require.Len(t, rows, 1)
		row, ok := rows[0].(map[string]any)
		require.True(t, ok)
		for _, field := range []string{"stage", "count", "elapsed_ms", "failed"} {
			assert.Contains(t, row, field, "%s must be present in %s", field, section)
		}
	}
}

func TestProgressWriter_closedOutputDoesNotFailOrRepeatWarnings(t *testing.T) {
	writer := newProgressWriter(errWriter{})

	assert.NotPanics(t, func() {
		writer.WriteEvent(progressEvent())
		writer.WriteEvent(progressEvent())
	})
	assert.True(t, writer.warned)
}

func TestNoUI_writesProgressImmediatelyToItsErrorChannel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	none := &NoUI{
		out:      &stdout,
		err:      &stderr,
		progress: newProgressWriter(&stderr),
	}

	require.NoError(t, none.Handle(progressEvent()))
	assert.Empty(t, stdout.String(), "progress must not use the SBOM output channel")
	assert.Contains(t, stderr.String(), `"event":"cataloging-progress"`)
	assert.Empty(t, none.finalizeEvents, "progress is emitted immediately, not deferred to teardown")
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken pipe")
}
