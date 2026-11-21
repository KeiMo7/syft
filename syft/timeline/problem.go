package timeline

import "fmt"

// Problem kinds.
const (
	// ProblemCorruptRecord is a complete journal line that cannot be decoded or validated.
	ProblemCorruptRecord = "corrupt-record"

	// ProblemInterruptedWrite is an unterminated trailing line, which is what a process killed
	// in the middle of an append leaves behind.
	ProblemInterruptedWrite = "interrupted-write"

	// ProblemConflict is two or more different snapshots sharing one timestamp.
	ProblemConflict = "conflict"

	// ProblemOutOfOrder is a record whose timestamp is older than the record before it. Both
	// writers keep the journal ordered by timestamp, so this only appears in a hand-edited file.
	ProblemOutOfOrder = "out-of-order"
)

// Problem describes a damaged or ambiguous part of the journal. Problems never cause the rest of
// the history to be discarded: each one names the exact location and states what is lost.
type Problem struct {
	// Kind is one of the Problem* constants.
	Kind string `json:"kind"`

	// Line is the 1-based line number in the journal file.
	Line int `json:"line,omitempty"`

	// SnapshotID identifies the record involved, when it could be decoded.
	SnapshotID string `json:"snapshotID,omitempty"`

	// Message explains what is wrong.
	Message string `json:"message"`

	// Impact states the consequence for the timeline.
	Impact string `json:"impact"`

	// Authoritative names the record that was used, for conflicts.
	Authoritative string `json:"authoritative,omitempty"`

	// Ignored names the records that were not used, for conflicts.
	Ignored []string `json:"ignored,omitempty"`
}

func corruptProblem(line int, err error) Problem {
	return Problem{
		Kind:    ProblemCorruptRecord,
		Line:    line,
		Message: fmt.Sprintf("journal line %d is not a valid snapshot record: %v", line, err),
		Impact:  "this snapshot is excluded; every other snapshot remains available and the timeline is built without it",
	}
}

func interruptedProblem(line int) Problem {
	return Problem{
		Kind:    ProblemInterruptedWrite,
		Line:    line,
		Message: fmt.Sprintf("journal line %d is an incomplete trailing record", line),
		Impact:  "the interrupted append is ignored; all records written before it are intact",
	}
}

func conflictProblem(line int, timestamp, winner string, losers []string) Problem {
	return Problem{
		Kind:          ProblemConflict,
		Line:          line,
		SnapshotID:    winner,
		Message:       fmt.Sprintf("multiple different snapshots share timestamp %s; %s is authoritative and supersedes %v", timestamp, winner, losers),
		Impact:        "only the authoritative snapshot is applied; the ignored snapshots remain on disk but do not affect the timeline",
		Authoritative: winner,
		Ignored:       losers,
	}
}

func outOfOrderProblem(line int, timestamp, previous string) Problem {
	return Problem{
		Kind:    ProblemOutOfOrder,
		Line:    line,
		Message: fmt.Sprintf("journal line %d has timestamp %s, older than the preceding record at %s", line, timestamp, previous),
		Impact:  "the file is not in chronological order; the record is still applied, but re-import the history to restore the canonical ordering",
	}
}
