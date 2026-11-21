package timeline

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// errStopReplay unwinds the line reader once the requested time range has been covered.
var errStopReplay = errors.New("stop replay")

// Read derives the timeline for the given query.
//
// The journal is streamed one line at a time; it is never loaded whole. Only compact per-component
// state is kept, so memory grows with the number of distinct components rather than with the number
// of snapshots or the size of their raw JSON. Query.Limit caps retained changes, and Query.Until
// stops the scan once the requested time range has been covered.
//
// Damaged lines are reported in Problems and skipped; they never cause the remaining history to be
// discarded. A contradictory timestamp is resolved deterministically: the record with the smallest
// snapshot identity is authoritative, so the result never depends on file order.
func (s *Store) Read(q Query) (*Timeline, error) {
	b := newTimelineBuilder(q)
	problems, err := s.replay(b)
	if err != nil {
		return nil, err
	}

	timeline := b.timeline()
	timeline.Problems = problems
	return timeline, nil
}

// Stream derives the timeline and calls emit for each change as it is produced, in chronological
// order. Only per-component state is retained, so a caller can export a very large history without
// holding the derived timeline in memory. The returned TimeRange covers the records that were read
// and count is the number of changes emitted.
func (s *Store) Stream(q Query, emit func(Change) error) (TimeRange, int, error) {
	b := newTimelineBuilder(q)
	b.emitFn = emit
	if _, err := s.replay(b); err != nil {
		return b.timeRange, b.changes, err
	}
	return b.timeRange, b.changes, nil
}

// replay reads the journal, resolves conflicts group by group, and applies each authoritative
// record to the builder. It returns the problems found while reading.
//
// Both Append and Import keep the journal sorted by timestamp, so records that share a timestamp
// are contiguous and can be resolved one group at a time instead of buffering the whole file.
func (s *Store) replay(b *timelineBuilder) ([]Problem, error) {
	f, err := os.Open(s.JournalPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to open history journal %q: %w", s.JournalPath(), err)
	}
	defer func() { _ = f.Close() }()

	r := &journalReplay{b: b}
	if err := eachJournalLine(f, r.consume); err != nil && !errors.Is(err, errStopReplay) {
		return r.problems, err
	}
	if err := r.flush(); err != nil {
		return r.problems, err
	}
	if r.tornLine > 0 {
		r.problems = append(r.problems, interruptedProblem(r.tornLine))
	}

	return r.problems, nil
}

// journalReplay folds journal lines into the builder, buffering one timestamp group at a time so
// that conflicting records can be resolved without holding the whole file.
type journalReplay struct {
	b         *timelineBuilder
	problems  []Problem
	group     []journalLineRecord
	groupTime string
	groupLine int
	lastTime  string
	tornLine  int
}

func (r *journalReplay) consume(line journalLine) error {
	if line.incomplete {
		r.tornLine = line.number
		return nil
	}

	rec, decodeErr := decodeRecord(line.data)
	if decodeErr != nil {
		// a corrupt line between two timestamp groups is reported on its own and does not
		// disturb the groups around it
		if err := r.flush(); err != nil {
			return err
		}
		r.problems = append(r.problems, corruptProblem(line.number, decodeErr))
		return nil
	}

	if r.groupTime != "" && rec.Timestamp != r.groupTime {
		if err := r.flush(); err != nil {
			return err
		}
		if r.b.until != nil && rec.Timestamp > FormatTimestamp(*r.b.until) {
			// records are ordered, so everything from here on is past the requested range
			return errStopReplay
		}
	}

	if r.groupTime != rec.Timestamp {
		r.groupTime = rec.Timestamp
		r.groupLine = line.number
	}
	r.group = append(r.group, journalLineRecord{line: line.number, rec: &rec})
	return nil
}

func (r *journalReplay) flush() error {
	if len(r.group) == 0 {
		return nil
	}

	authority, groupProblems := resolveGroup(r.group, r.groupTime, r.groupLine, r.lastTime)
	r.problems = append(r.problems, groupProblems...)
	r.group = r.group[:0]
	r.lastTime = r.groupTime

	if authority == nil {
		return nil
	}
	return r.b.apply(*authority)
}

// resolveGroup picks the authoritative record for one timestamp. Duplicate lines for the same
// snapshot collapse silently; genuinely different snapshots at the same timestamp are reported as
// a conflict that names the authoritative snapshot and lists the ignored ones.
func resolveGroup(group []journalLineRecord, timestamp string, line int, previous string) (*Record, []Problem) {
	byID := make(map[string]Record, len(group))
	ids := make([]string, 0, len(group))
	for _, entry := range group {
		if entry.rec == nil {
			continue
		}
		if _, ok := byID[entry.rec.SnapshotID]; ok {
			continue
		}
		byID[entry.rec.SnapshotID] = *entry.rec
		ids = append(ids, entry.rec.SnapshotID)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	sort.Strings(ids)
	authority := byID[ids[0]]

	var problems []Problem
	if len(ids) > 1 {
		problems = append(problems, conflictProblem(line, timestamp, ids[0], ids[1:]))
	}
	if previous != "" && timestamp < previous {
		problems = append(problems, outOfOrderProblem(line, timestamp, previous))
	}

	return &authority, problems
}

// ImportFile imports one SBOM document into the history. The format is detected with the regular
// SBOM decoders.
func (s *Store) ImportFile(path string, at time.Time) (Record, bool, error) {
	doc, err := decodeDocument(path)
	if err != nil {
		return Record{}, false, err
	}
	rec := NewRecord(*doc, at)
	added, err := s.Import(rec)
	return rec, added, err
}

// ImportTime returns a stable fallback timestamp for a document that carries none of its own.
func ImportTime(path string) time.Time {
	if info, err := os.Stat(path); err == nil {
		return NormalizeTimestamp(info.ModTime())
	}
	return NormalizeTimestamp(time.Now())
}
