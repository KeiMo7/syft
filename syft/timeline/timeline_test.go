package timeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := ParseTimestamp(value)
	require.NoError(t, err)
	return parsed
}

func testPackage(name, version, purl string) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.NpmPkg,
		PURL:      purl,
		Locations: file.NewLocationSet(file.NewLocation("/app/package-lock.json")),
	}
	p.SetID()
	return p
}

func testSBOM(pkgs ...pkg.Package) sbom.SBOM {
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(pkgs...),
		},
		Source: source.Description{
			ID:       "source-id",
			Name:     "some-image",
			Version:  "latest",
			Metadata: source.ImageMetadata{UserInput: "some-image:latest"},
		},
		Descriptor: sbom.Descriptor{Name: "syft", Version: "v0.0.0-test"},
	}
}

func testRecord(t *testing.T, when string, pkgs ...pkg.Package) Record {
	t.Helper()
	return NewRecord(testSBOM(pkgs...), at(t, when))
}

func lodash(version string) pkg.Package {
	return testPackage("lodash", version, "pkg:npm/lodash@"+version)
}

func react(version string) pkg.Package {
	return testPackage("react", version, "pkg:npm/react@"+version)
}

func TestAppend_NormalTimeline(t *testing.T) {
	store := Open(t.TempDir())

	// react appears later than lodash; lodash changes version in the middle
	added, err := store.Append(testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	require.NoError(t, err)
	require.True(t, added)

	added, err = store.Append(testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.20")))
	require.NoError(t, err)
	require.True(t, added)

	added, err = store.Append(testRecord(t, "2026-03-01T00:00:00Z", lodash("4.17.21"), react("18.2.0")))
	require.NoError(t, err)
	require.True(t, added)

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	require.Equal(t, 3, timeline.Snapshots)
	assert.Empty(t, timeline.Problems)

	byKey := map[string]ComponentTimeline{}
	for _, c := range timeline.Components {
		byKey[c.Name] = c
	}

	lodashTimeline := byKey["lodash"]
	assert.Equal(t, "2026-01-01T00:00:00.000Z", lodashTimeline.FirstSeen)
	assert.Equal(t, "2026-03-01T00:00:00.000Z", lodashTimeline.LastSeen)
	assert.True(t, lodashTimeline.Present)
	assert.Equal(t, "4.17.21", lodashTimeline.Version)

	// only the version change is a transition; the unchanged snapshot contributes nothing
	require.Len(t, lodashTimeline.Changes, 2)
	assert.Equal(t, KindAdded, lodashTimeline.Changes[0].Kind)
	assert.Equal(t, "2026-01-01T00:00:00.000Z", lodashTimeline.Changes[0].Timestamp)
	assert.Equal(t, KindChanged, lodashTimeline.Changes[1].Kind)
	assert.Equal(t, "4.17.20", lodashTimeline.Changes[1].FromVersion)
	assert.Equal(t, "4.17.21", lodashTimeline.Changes[1].ToVersion)
	assert.Equal(t, "2026-03-01T00:00:00.000Z", lodashTimeline.Changes[1].Timestamp)

	require.Len(t, byKey["react"].Changes, 1)
	assert.Equal(t, KindAdded, byKey["react"].Changes[0].Kind)
	assert.Equal(t, "2026-03-01T00:00:00.000Z", byKey["react"].FirstSeen)
}

func TestAppend_RebuildWithoutContentChangeCreatesNoTransition(t *testing.T) {
	store := Open(t.TempDir())

	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21"), react("18.2.0")))
	requireAppended(t, store, testRecord(t, "2026-01-02T00:00:00Z", lodash("4.17.21"), react("18.2.0")))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	require.Equal(t, 2, timeline.Snapshots)

	total := 0
	for _, c := range timeline.Components {
		// one addition at the initial snapshot, nothing afterwards
		assert.Len(t, c.Changes, 1, "component %q should only have its initial addition", c.Key)
		assert.Equal(t, KindAdded, c.Changes[0].Kind)
		assert.Equal(t, "2026-01-01T00:00:00.000Z", c.FirstSeen)
		// the component is still observed in the rebuild, even though nothing changed
		assert.Equal(t, "2026-01-02T00:00:00.000Z", c.LastSeen)
		total += len(c.Changes)
	}
	assert.Equal(t, 2, total)

	// no removals were recorded, and no timestamp carries a change after the first
	require.Len(t, timeline.Timepoints, 1)
	assert.Equal(t, "2026-01-01T00:00:00.000Z", timeline.Timepoints[0].Timestamp)
}

func TestAppend_RejectsTimeGoingBackwards(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-03-01T00:00:00Z", lodash("4.17.21")))

	added, err := store.Append(testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.20")))
	require.ErrorIs(t, err, ErrOutOfOrder)
	assert.False(t, added)
	assert.Contains(t, err.Error(), "2026-03-01T00:00:00.000Z")

	// the rejected record did not modify the history
	timeline, readErr := store.Read(Query{})
	require.NoError(t, readErr)
	require.Equal(t, 1, timeline.Snapshots)
}

func TestAppend_IdenticalSnapshotIsNotDuplicated(t *testing.T) {
	store := Open(t.TempDir())
	rec := testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21"))

	added, err := store.Append(rec)
	require.NoError(t, err)
	require.True(t, added)

	added, err = store.Append(rec)
	require.NoError(t, err)
	assert.False(t, added)

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	assert.Equal(t, 1, timeline.Snapshots)
}

func TestAppend_InterruptedWriteIsRepairedAndPriorRecordsRemainReadable(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21")))

	journal := store.JournalPath()
	before, err := os.ReadFile(journal)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(before), "\n"))

	// simulate a process killed after it had written part of the next record: the first record
	// stays whole and a torn second line is appended
	next, err := marshalRecordLine(testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.22")))
	require.NoError(t, err)
	torn := append(append([]byte{}, before...), next[:len(next)/2]...)
	require.NoError(t, os.WriteFile(journal, torn, 0o644))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	require.Equal(t, 1, timeline.Snapshots)
	require.NotEmpty(t, timeline.Problems)
	assert.Equal(t, ProblemInterruptedWrite, timeline.Problems[0].Kind)

	// the next append repairs the torn tail: the old record stays complete and the new one is
	// complete too, so the file holds exactly two well-formed lines
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.22")))

	repaired, err := os.ReadFile(journal)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(string(repaired), "\n"), "the journal must end on a record boundary")
	require.Equal(t, 2, strings.Count(string(repaired), "\n"))
	for _, line := range strings.Split(strings.TrimSuffix(string(repaired), "\n"), "\n") {
		_, decodeErr := decodeRecord([]byte(line))
		assert.NoError(t, decodeErr, "every line after repair must be a complete record")
	}

	timeline, err = store.Read(Query{})
	require.NoError(t, err)
	assert.Equal(t, 2, timeline.Snapshots)
	assert.Empty(t, timeline.Problems)
}

func TestRead_CorruptLineIsLocalizedAndRestIsKept(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21")))
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.22")))
	requireAppended(t, store, testRecord(t, "2026-03-01T00:00:00Z", lodash("4.17.23")))

	journal := store.JournalPath()
	lines, err := os.ReadFile(journal)
	require.NoError(t, err)
	split := strings.Split(strings.TrimSuffix(string(lines), "\n"), "\n")
	require.Len(t, split, 3)
	split[1] = `{"recordVersion":1,"snapshotID":"sha256:deadbeef","timestamp":"2026-02-01T00:00:00.000Z","components":[]}`
	require.NoError(t, os.WriteFile(journal, []byte(strings.Join(split, "\n")+"\n"), 0o644))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)

	// the two intact snapshots still form a timeline
	require.Equal(t, 2, timeline.Snapshots)
	require.Len(t, timeline.Problems, 1)
	problem := timeline.Problems[0]
	assert.Equal(t, ProblemCorruptRecord, problem.Kind)
	assert.Equal(t, 2, problem.Line)
	assert.Contains(t, problem.Impact, "every other snapshot remains available")

	require.Len(t, timeline.Components, 1)
	require.Len(t, timeline.Components[0].Changes, 2)
	assert.Equal(t, "4.17.21", timeline.Components[0].Changes[0].ToVersion)
	assert.Equal(t, "4.17.23", timeline.Components[0].Changes[1].ToVersion)
}

func TestRead_ConflictingTimestampNamesTheAuthority(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)

	first := testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21"))
	second := testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.22"))
	require.NotEqual(t, first.SnapshotID, second.SnapshotID)

	// a conflict cannot be produced by Append (which orders live scans and rejects older ones);
	// it appears when a history was merged or hand-edited, so write both lines directly
	var journal []byte
	for _, rec := range []Record{first, second} {
		line, err := marshalRecordLine(rec)
		require.NoError(t, err)
		journal = append(journal, line...)
	}
	require.NoError(t, os.WriteFile(store.JournalPath(), journal, 0o644))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)

	require.Len(t, timeline.Problems, 1)
	problem := timeline.Problems[0]
	assert.Equal(t, ProblemConflict, problem.Kind)
	require.NotEmpty(t, problem.Authoritative)
	require.Len(t, problem.Ignored, 1)
	assert.Contains(t, problem.Message, "authoritative")

	winner := first.SnapshotID
	if second.SnapshotID < first.SnapshotID {
		winner = second.SnapshotID
	}
	assert.Equal(t, winner, problem.Authoritative)

	// the timeline reflects exactly the authoritative snapshot
	require.Equal(t, 1, timeline.Snapshots)
	require.Len(t, timeline.Components, 1)
	expected := "4.17.21"
	if winner == second.SnapshotID {
		expected = "4.17.22"
	}
	assert.Equal(t, expected, timeline.Components[0].Version)
}

func TestImport_OrderDoesNotAffectTimeline(t *testing.T) {
	records := []Record{
		testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")),
		testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21")),
		testRecord(t, "2026-03-01T00:00:00Z", lodash("4.17.22"), react("18.2.0")),
	}

	forward := Open(t.TempDir())
	for _, rec := range records {
		added, err := forward.Import(rec)
		require.NoError(t, err)
		require.True(t, added)
	}

	backward := Open(t.TempDir())
	for i := len(records) - 1; i >= 0; i-- {
		added, err := backward.Import(records[i])
		require.NoError(t, err)
		require.True(t, added)
	}

	// re-importing everything changes nothing
	for _, rec := range records {
		added, err := backward.Import(rec)
		require.NoError(t, err)
		assert.False(t, added)
	}

	forwardTimeline, err := forward.Read(Query{})
	require.NoError(t, err)
	backwardTimeline, err := backward.Read(Query{})
	require.NoError(t, err)

	assert.Equal(t, stripProblems(forwardTimeline), stripProblems(backwardTimeline))
	assert.Equal(t, 3, forwardTimeline.Snapshots)

	// the journal files are byte-identical regardless of import order
	forwardJournal, err := os.ReadFile(forward.JournalPath())
	require.NoError(t, err)
	backwardJournal, err := os.ReadFile(backward.JournalPath())
	require.NoError(t, err)
	assert.Equal(t, string(forwardJournal), string(backwardJournal))
}

func TestRead_QueryByComponentAndTimeRange(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21"), react("18.2.0")))
	requireAppended(t, store, testRecord(t, "2026-03-01T00:00:00Z", lodash("4.17.21"), react("18.3.0")))

	t.Run("by component name", func(t *testing.T) {
		timeline, err := store.Read(Query{Component: "react"})
		require.NoError(t, err)
		require.Len(t, timeline.Components, 1)
		assert.Equal(t, "react", timeline.Components[0].Name)
		require.Len(t, timeline.Components[0].Changes, 2)
	})

	t.Run("by purl", func(t *testing.T) {
		timeline, err := store.Read(Query{Component: "pkg:npm/lodash@4.17.21"})
		require.NoError(t, err)
		require.Len(t, timeline.Components, 1)
		assert.Equal(t, "lodash", timeline.Components[0].Name)
	})

	t.Run("by time range reports only changes inside the window", func(t *testing.T) {
		since := at(t, "2026-02-01T00:00:00Z")
		timeline, err := store.Read(Query{Since: &since})
		require.NoError(t, err)

		byName := map[string]ComponentTimeline{}
		for _, c := range timeline.Components {
			byName[c.Name] = c
		}
		require.Contains(t, byName, "react")
		// react's first appearance is inside the window
		assert.Equal(t, "2026-02-01T00:00:00.000Z", byName["react"].FirstSeen)
		// lodash existed before the window; only its version change is reported
		require.Len(t, byName["lodash"].Changes, 1)
		assert.Equal(t, KindChanged, byName["lodash"].Changes[0].Kind)
		assert.Equal(t, "2026-01-01T00:00:00.000Z", byName["lodash"].FirstSeen)
	})

	t.Run("until bounds the reported changes but keeps prior state", func(t *testing.T) {
		until := at(t, "2026-02-01T00:00:00Z")
		timeline, err := store.Read(Query{Until: &until})
		require.NoError(t, err)
		byName := map[string]ComponentTimeline{}
		for _, c := range timeline.Components {
			byName[c.Name] = c
		}
		require.Contains(t, byName, "lodash")
		assert.Len(t, byName["lodash"].Changes, 2) // added + version change
		assert.Len(t, byName["react"].Changes, 1)  // added
	})

	t.Run("limit truncates changes", func(t *testing.T) {
		timeline, err := store.Read(Query{Limit: 2})
		require.NoError(t, err)
		assert.True(t, timeline.Truncated)
	})
}

func TestRead_BothViewsAgree(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21"), react("18.2.0")))
	requireAppended(t, store, testRecord(t, "2026-03-01T00:00:00Z", react("18.3.0")))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)

	var fromComponents []Change
	for _, c := range timeline.Components {
		fromComponents = append(fromComponents, c.Changes...)
	}
	var fromTimepoints []Change
	for _, tp := range timeline.Timepoints {
		fromTimepoints = append(fromTimepoints, tp.Changes...)
	}

	assert.ElementsMatch(t, fromComponents, fromTimepoints)
	assert.Equal(t, len(fromComponents), len(fromTimepoints))

	// lodash disappeared in the final snapshot
	for _, c := range timeline.Components {
		if c.Name == "lodash" {
			assert.False(t, c.Present)
			assert.Equal(t, "2026-03-01T00:00:00.000Z", c.RemovedAt)
		}
	}
}

func TestStore_SourceChangeIsAChange(t *testing.T) {
	store := Open(t.TempDir())

	fromRegistries := testPackage("lodash", "4.17.21", "pkg:npm/lodash@4.17.21?repository_url=https://registry.npmjs.org")
	fromMirror := testPackage("lodash", "4.17.21", "pkg:npm/lodash@4.17.21?repository_url=https://npm-mirror.internal")

	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", fromRegistries))
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", fromMirror))

	timeline, err := store.Read(Query{Component: "lodash"})
	require.NoError(t, err)
	require.Len(t, timeline.Components, 1)

	changes := timeline.Components[0].Changes
	require.Len(t, changes, 2)
	assert.Equal(t, KindChanged, changes[1].Kind)
	assert.Equal(t, "https://registry.npmjs.org", changes[1].FromSource)
	assert.Equal(t, "https://npm-mirror.internal", changes[1].ToSource)
	assert.Equal(t, "4.17.21", changes[1].FromVersion)
	assert.Equal(t, "4.17.21", changes[1].ToVersion)
}

func TestStore_StreamMatchesRead(t *testing.T) {
	store := Open(t.TempDir())
	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.20")))
	requireAppended(t, store, testRecord(t, "2026-02-01T00:00:00Z", lodash("4.17.21"), react("18.2.0")))

	timeline, err := store.Read(Query{})
	require.NoError(t, err)

	var streamed []Change
	_, count, err := store.Stream(Query{}, func(change Change) error {
		streamed = append(streamed, change)
		return nil
	})
	require.NoError(t, err)

	var expected []Change
	for _, tp := range timeline.Timepoints {
		expected = append(expected, tp.Changes...)
	}
	assert.Equal(t, expected, streamed)
	assert.Equal(t, len(expected), count)
}

func TestStore_MissingHistoryIsEmptyAndCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	store := Open(dir)

	timeline, err := store.Read(Query{})
	require.NoError(t, err)
	assert.True(t, timeline.Empty())

	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "reading a missing history must not create the directory")
}

func TestStore_AppendCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "history")
	store := Open(dir)

	requireAppended(t, store, testRecord(t, "2026-01-01T00:00:00Z", lodash("4.17.21")))

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestTimestamp_NormalizesToSingleFormat(t *testing.T) {
	tests := map[string]string{
		"2026-01-01T00:00:00Z":           "2026-01-01T00:00:00.000Z",
		"2026-01-01T02:00:00+02:00":      "2026-01-01T00:00:00.000Z",
		"2026-01-01T00:00:00.000Z":       "2026-01-01T00:00:00.000Z",
		"2026-01-01T00:00:00.123456789Z": "2026-01-01T00:00:00.123Z",
		"2026-01-01":                     "2026-01-01T00:00:00.000Z",
		"2026-01-01 00:00:00":            "2026-01-01T00:00:00.000Z",
		"2026-06-01T01:30:00.5-05:00":    "2026-06-01T06:30:00.500Z",
	}
	for input, expected := range tests {
		parsed, err := ParseTimestamp(input)
		require.NoError(t, err, input)
		assert.Equal(t, expected, FormatTimestamp(parsed), input)
	}

	_, err := ParseTimestamp("not a time")
	require.Error(t, err)
}

func TestIdentityKey_UsesOneDefinition(t *testing.T) {
	// packages that differ only by version or source must share a key
	base := testPackage("lodash", "4.17.20", "pkg:npm/lodash@4.17.20")
	bumped := testPackage("lodash", "4.17.21", "pkg:npm/lodash@4.17.21?repository_url=https://example.com")

	baseKey, _, _, _ := IdentityKey(base)
	bumpedKey, _, _, _ := IdentityKey(bumped)
	assert.Equal(t, baseKey, bumpedKey)

	// packages that differ in name or ecosystem must not
	other := testPackage("react", "4.17.20", "pkg:npm/react@4.17.20")
	otherKey, _, _, _ := IdentityKey(other)
	assert.NotEqual(t, baseKey, otherKey)

	// the same name in another ecosystem is a different component
	otherEcosystem := testPackage("lodash", "4.17.20", "pkg:pypi/lodash@4.17.20")
	otherEcosystemKey, _, _, _ := IdentityKey(otherEcosystem)
	assert.NotEqual(t, baseKey, otherEcosystemKey)
}

func TestComponentsFromSBOM_DeduplicatesDeterministically(t *testing.T) {
	// two records of the same component (e.g. found in two manifests) with different versions:
	// exactly one representative is kept and catalog order does not matter
	a := testPackage("lodash", "4.17.20", "pkg:npm/lodash@4.17.20")
	b := testPackage("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")

	forward := ComponentsFromSBOM(testSBOM(a, b))
	backward := ComponentsFromSBOM(testSBOM(b, a))
	assert.Equal(t, forward, backward)
	require.Len(t, forward, 1)
	assert.Equal(t, "4.17.20", forward[0].Version)
}

func requireAppended(t *testing.T, store *Store, rec Record) {
	t.Helper()
	added, err := store.Append(rec)
	require.NoError(t, err)
	require.True(t, added)
}

func stripProblems(timeline *Timeline) *Timeline {
	copied := *timeline
	copied.Problems = nil
	return &copied
}
