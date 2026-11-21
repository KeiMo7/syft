package timeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseLineReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lines.txt")
	content := "one\ntwo\nthree\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	require.NoError(t, err)

	r := &reverseLineReader{file: f, offset: info.Size()}
	var got []string
	for {
		line, err := r.previous()
		if err != nil {
			break
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		got = append(got, string(line))
	}

	assert.Equal(t, []string{"three", "two", "one"}, got)
}

func TestInspectTail_BoundedByOrdering(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)

	// a long run of historical snapshots followed by two at the newest timestamp
	for day := 1; day <= 31; day++ {
		ts := time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC)
		requireAppended(t, store, NewRecord(testSBOM(lodash("4.17.20")), ts))
	}

	newest := testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21"))
	line, err := marshalRecordLine(newest)
	require.NoError(t, err)
	f, err := os.OpenFile(store.JournalPath(), os.O_WRONLY|os.O_APPEND, 0o644)
	require.NoError(t, err)
	_, err = f.Write(line)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	point, err := inspectTail(store.JournalPath(), newest.Timestamp)
	require.NoError(t, err)
	assert.Equal(t, newest.Timestamp, point.newestTimestamp)
	assert.Contains(t, point.atTimestamp, newest.SnapshotID)

	// a timestamp no snapshot was recorded at stops the backward scan at the first older line
	absent := testRecord(t, "2026-01-10T12:00:00Z", lodash("4.17.20"))
	point, err = inspectTail(store.JournalPath(), absent.Timestamp)
	require.NoError(t, err)
	assert.Equal(t, newest.Timestamp, point.newestTimestamp, "the newest timestamp is still reported")
	assert.Empty(t, point.atTimestamp, "no record at the absent timestamp, and the scan stopped early")
}

func TestInspectTail_MissingJournal(t *testing.T) {
	point, err := inspectTail(filepath.Join(t.TempDir(), "absent.jsonl"), "2026-01-01T00:00:00.000Z")
	require.NoError(t, err)
	assert.Empty(t, point.newestTimestamp)
	assert.Empty(t, point.atTimestamp)
}
