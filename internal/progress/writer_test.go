package progress

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/event/monitor"
)

func TestEventWriter_writesJSONLandSwallowsClosedOutput(t *testing.T) {
	var out bytes.Buffer
	writer := NewEventWriter(&out)
	snapshot := monitor.CatalogingProgress{
		Event: monitor.CatalogingProgressEvent,
		Stages: []monitor.CatalogingStage{{
			Stage:     "python-package-cataloger",
			Count:     2,
			ElapsedMS: 3,
			Elapsed:   "3ms",
			State:     "completed",
			Layer:     0,
			Parser:    "python",
		}},
	}

	require.NoError(t, writer.Write(snapshot))

	var decoded monitor.CatalogingProgress
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out.Bytes()), &decoded))
	assert.Equal(t, monitor.CatalogingProgressEvent, decoded.Event)
	assert.Equal(t, int64(2), decoded.Stages[0].Count)

	closed := NewEventWriter(errWriter{})
	assert.NoError(t, closed.Write(snapshot))
	assert.NoError(t, closed.Write(snapshot))
	assert.True(t, closed.warned)
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken pipe")
}
