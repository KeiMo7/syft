package timeline

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentAppends_NoTornRecords verifies the core append guarantee: however many scans
// record at once, every line in the journal is a complete, valid record.
func TestConcurrentAppends_NoTornRecords(t *testing.T) {
	dir := t.TempDir()

	const writers, perWriter = 8, 5
	var wg sync.WaitGroup
	reported := make(chan error, writers*perWriter)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			recorder := NewRecorder(dir, func(err error) { reported <- err })
			for i := 0; i < perWriter; i++ {
				version := fmt.Sprintf("%d.%d.0", w, i)
				recorder.Record(testSBOM(testPackage(fmt.Sprintf("pkg-%d-%d", w, i), version, "pkg:npm/pkg-"+version)))
			}
		}(w)
	}
	wg.Wait()
	close(reported)

	for err := range reported {
		t.Errorf("a concurrent append failed: %v", err)
	}

	store := Open(dir)
	raw, err := os.ReadFile(store.JournalPath())
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(string(raw), "\n"), "the journal must end on a record boundary")

	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	require.Len(t, lines, writers*perWriter, "each append must produce exactly one record")
	for i, line := range lines {
		_, decodeErr := decodeRecord([]byte(line))
		assert.NoError(t, decodeErr, "line %d must be a complete record", i+1)
	}

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	assert.Equal(t, writers*perWriter, timeline.Snapshots)
	assert.Empty(t, timeline.Problems)
}

// TestReadDuringAppend_SeesOnlyCompleteRecords models the kill/restart guarantee from the reader's
// point of view: while appends are in flight, a reader never observes a partially written record.
func TestReadDuringAppend_SeesOnlyCompleteRecords(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)

	recorder := NewRecorder(dir, nil)
	for i := 0; i < 3; i++ {
		recorder.Record(testSBOM(testPackage(fmt.Sprintf("pkg-%d", i), "1.0.0", fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i))))
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			recorder.Record(testSBOM(testPackage("hot", fmt.Sprintf("1.0.%d", i), fmt.Sprintf("pkg:npm/hot@1.0.%d", i))))
		}
	}()

	for i := 0; i < 20; i++ {
		timeline, err := store.Read(Query{})
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("a reader failed while appends were in flight: %v", err)
		}
		assert.Empty(t, timeline.Problems, "a concurrent append must not be visible as a problem")
	}
	close(stop)
	wg.Wait()
}
