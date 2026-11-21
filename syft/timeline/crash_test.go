package timeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKillDuringWriteLeavesOnlyCompleteRecordsFile reproduces the subprocess scenario in-process:
// the first record is complete, the second one was cut off by a kill, and the reader must return
// exactly the first record plus a localized problem, then the next append must repair the file.
func TestKillDuringWriteLeavesOnlyCompleteRecordsFile(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))

	complete, err := os.ReadFile(store.JournalPath())
	require.NoError(t, err)

	torn, err := marshalRecordLine(testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21")))
	require.NoError(t, err)
	// crash after writing half the second record
	require.NoError(t, os.WriteFile(store.JournalPath(), append(append([]byte{}, complete...), torn[:len(torn)/2]...), 0o644))

	got, err := store.Read(Query{})
	require.NoError(t, err)
	require.Equal(t, 1, got.Snapshots)
	require.Len(t, got.Problems, 1)
	assert.Equal(t, ProblemInterruptedWrite, got.Problems[0].Kind)
	assert.Equal(t, 2, got.Problems[0].Line)

	// the surviving record is exactly the complete one
	lines := strings.Split(strings.TrimSuffix(string(complete), "\n"), "\n")
	require.Len(t, lines, 1)
	_, err = decodeRecord([]byte(lines[0]))
	require.NoError(t, err)

	// restart: the next append repairs the tail and both records are readable
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21")))
	after, err := store.Read(Query{})
	require.NoError(t, err)
	assert.Equal(t, 2, after.Snapshots)
	assert.Empty(t, after.Problems)

	raw, err := os.ReadFile(filepath.Join(dir, JournalFileName))
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(string(raw), "\n"))
}
