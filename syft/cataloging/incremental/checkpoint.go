package incremental

import (
	"sync"
	"time"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/sbom"
)

// DefaultCheckpointInterval is the minimum time between partial checkpoint
// writes.
const DefaultCheckpointInterval = 5 * time.Second

// CheckpointWriter atomically persists partial catalog state. It is safe for
// concurrent use by catalog tasks.
type CheckpointWriter struct {
	path     string
	interval time.Duration

	mutex          sync.Mutex
	lastWrite      time.Time
	processedPaths []string
}

// NewCheckpointWriter creates a checkpoint writer for path.
func NewCheckpointWriter(path string) *CheckpointWriter {
	return &CheckpointWriter{
		path:     path,
		interval: DefaultCheckpointInterval,
	}
}

// Save writes a partial checkpoint, subject to the checkpoint interval.
func (w *CheckpointWriter) Save(document *sbom.SBOM) {
	if w == nil || w.path == "" || document == nil {
		return
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	now := time.Now()
	if !w.lastWrite.IsZero() && now.Sub(w.lastWrite) < w.interval {
		return
	}
	if err := WriteCheckpointAtomic(w.path, document, false, w.processedPaths); err != nil {
		log.WithFields("path", w.path, "error", err).Warn("unable to write incremental checkpoint")
		return
	}
	w.lastWrite = now
}

// MarkProcessed records paths represented by the checkpoint. The list is
// diagnostic; merge safety is derived from packages and file coordinates.
func (w *CheckpointWriter) MarkProcessed(paths []string) {
	if w == nil {
		return
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.processedPaths = append(w.processedPaths[:0], paths...)
}

// SaveComplete writes the final, complete checkpoint regardless of the partial
// write interval.
func (w *CheckpointWriter) SaveComplete(document *sbom.SBOM) error {
	if w == nil || w.path == "" {
		return nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()
	if err := WriteCheckpointAtomic(w.path, document, true, w.processedPaths); err != nil {
		return err
	}
	w.lastWrite = time.Now()
	return nil
}
