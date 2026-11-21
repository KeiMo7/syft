package timeline

import (
	"fmt"
	"time"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/sbom"
)

// ErrFunc receives the errors a caller must not fail on. The scan uses it to turn a broken or
// unwritable history into a warning, so producing the SBOM is never blocked by the optional
// history.
type ErrFunc func(error)

// Recorder appends scan results to a Store and reports failures instead of returning them.
type Recorder struct {
	store   *Store
	onError ErrFunc
	now     func(time.Time) time.Time
}

// NewRecorder returns a recorder writing to dir. When dir is empty the recorder is a no-op, so the
// caller does not need to branch on whether the feature is enabled.
func NewRecorder(dir string, onError ErrFunc) *Recorder {
	if onError == nil {
		onError = func(err error) { log.Warnf("timeline: %v", err) }
	}
	return &Recorder{
		store:   Open(dir),
		onError: onError,
		now:     func(now time.Time) time.Time { return now },
	}
}

// NewRecorderAt is like NewRecorder but takes the clock, which makes the recorded timestamp
// injectable in tests. The clock receives the time sampled under the append lock.
func NewRecorderAt(dir string, now func(time.Time) time.Time, onError ErrFunc) *Recorder {
	r := NewRecorder(dir, onError)
	r.now = now
	return r
}

// Enabled reports whether history recording is active.
func (r *Recorder) Enabled() bool {
	return r != nil && r.store != nil && r.store.Dir() != ""
}

// Record appends an observation of s. It never returns an error: a failure is delivered to the
// configured ErrFunc, so the scan continues and only the history for this run is missing.
//
// The timestamp is taken while the append is serialized, which keeps concurrent live scans in the
// order they were actually recorded.
func (r *Recorder) Record(s sbom.SBOM) {
	if !r.Enabled() {
		return
	}

	_, err := r.store.AppendNow(func(now time.Time) Record {
		return NewRecord(s, r.now(now))
	})
	if err != nil {
		if r.onError != nil {
			r.onError(fmt.Errorf("unable to record snapshot in %q: %w", r.store.Dir(), err))
		}
	}
}

// Store exposes the underlying store for the timeline command.
func (r *Recorder) Store() *Store {
	if r == nil {
		return nil
	}
	return r.store
}
