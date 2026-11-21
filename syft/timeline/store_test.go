package timeline

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

func TestAppend_SameTimestampIsOrderedRatherThanConflicting(t *testing.T) {
	store := Open(t.TempDir())

	// two scans can land inside the same second; they must both be recorded, in order, without
	// turning into a conflict on read
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21")))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	assert.Equal(t, 2, timeline.Snapshots)
	assert.Empty(t, timeline.Problems)

	require.Len(t, timeline.Components, 1)
	changes := timeline.Components[0].Changes
	require.Len(t, changes, 2)
	assert.Equal(t, KindAdded, changes[0].Kind)
	assert.Equal(t, KindChanged, changes[1].Kind)
	assert.Equal(t, "4.17.21", changes[1].ToVersion)
	assert.Equal(t, "2026-01-01T00:00:00.001Z", changes[1].Timestamp)
}

func TestRecorder_ReportsFailuresInsteadOfFailing(t *testing.T) {
	// make the history path an existing file so creating the directory fails
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "history")
	require.NoError(t, os.WriteFile(historyPath, []byte("not a directory"), 0o644))

	var reported error
	recorder := NewRecorder(historyPath, func(err error) { reported = err })
	require.True(t, recorder.Enabled())

	recorder.Record(testSBOM(lodash("4.17.21")))

	require.Error(t, reported)
	assert.Contains(t, reported.Error(), "unable to record snapshot")

	// the SBOM itself is untouched by the failure
	assert.Equal(t, 1, testSBOM(lodash("4.17.21")).Artifacts.Packages.PackageCount())
}

func TestRecorder_DisabledWhenNoDirectory(t *testing.T) {
	var called bool
	recorder := NewRecorder("", func(error) { called = true })
	assert.False(t, recorder.Enabled())

	recorder.Record(testSBOM(lodash("4.17.21")))
	assert.False(t, called, "a disabled recorder must not report anything")
}

func TestRecorder_RecordsAtInjectedTime(t *testing.T) {
	dir := t.TempDir()
	fixed := at(t, "2026-05-05T05:05:05Z")
	recorder := NewRecorderAt(dir, func(time.Time) time.Time { return fixed }, nil)

	recorder.Record(testSBOM(lodash("4.17.21")))

	timeline, err := Open(dir).Read(Query{})
	require.NoError(t, err)
	require.Equal(t, 1, timeline.Snapshots)
	assert.Equal(t, "2026-05-05T05:05:05.000Z", timeline.Range.From)
}

func TestImportFile_RoundTripsThroughSyftJSON(t *testing.T) {
	dir := t.TempDir()
	docPath := filepath.Join(dir, "old.syft.json")

	f, err := os.Create(docPath)
	require.NoError(t, err)
	require.NoError(t, syftjson.NewFormatEncoder().Encode(f, testSBOM(lodash("4.17.20"), react("18.2.0"))))
	require.NoError(t, f.Close())

	store := Open(filepath.Join(dir, "history"))
	rec, added, err := store.ImportFile(docPath, at(t, "2026-01-01T00:00:00Z"))
	require.NoError(t, err)
	require.True(t, added)
	assert.Equal(t, 2, len(rec.Components))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	require.Equal(t, 1, timeline.Snapshots)
	assert.Equal(t, 2, len(timeline.Components))

	// importing the same document again changes nothing
	_, added, err = store.ImportFile(docPath, at(t, "2026-01-01T00:00:00Z"))
	require.NoError(t, err)
	assert.False(t, added)
}

func TestErrOutOfOrder_DistinctFromValidationErrors(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21")))

	_, err := store.Append(testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	require.True(t, errors.Is(err, ErrOutOfOrder))

	// Import tolerates the same record because backfill order is not chronological
	_, err = store.Import(testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	require.NoError(t, err)
}

func TestRecord_ValidateRejectsTamperedContent(t *testing.T) {
	rec := testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21"))
	require.NoError(t, rec.Validate())

	rec.Components[0].Version = "9.9.9"
	require.ErrorContains(t, rec.Validate(), "does not match record content")
}

func TestReadImageSourceTypeIsRecorded(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21")))

	// the source descriptor is informational and is preserved verbatim for reviewers
	lines, err := os.ReadFile(store.JournalPath())
	require.NoError(t, err)
	assert.Contains(t, string(lines), `"type":"image"`)
	assert.Contains(t, string(lines), `"name":"some-image"`)
}

func TestNewRecordWithEmptySBOM(t *testing.T) {
	s := sbom.SBOM{}
	rec := NewRecord(s, at(t, "2026-01-01T00:00:00Z"))
	require.NoError(t, rec.Validate())
	assert.Empty(t, rec.Components)
}
