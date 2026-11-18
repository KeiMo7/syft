package progress

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/monitor"
)

// EventWriter serializes snapshots as one JSON object per line. Write failures are swallowed and
// warn once, so a closed progress pipe cannot fail or stall the scan.
type EventWriter struct {
	mu     sync.Mutex
	out    io.Writer
	warned bool
}

func NewEventWriter(out io.Writer) *EventWriter {
	return &EventWriter{out: out}
}

func (w *EventWriter) Write(snapshot monitor.CatalogingProgress) error {
	ignoreBrokenPipe()

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.warned {
		return nil
	}

	line, err := json.Marshal(snapshot)
	if err == nil {
		_, err = fmt.Fprintln(w.out, string(line))
	}
	if err == nil {
		return nil
	}

	w.warned = true
	log.WithFields("error", err).Warn("unable to report cataloging progress; further progress output will be suppressed")
	return nil
}
