package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/parsers"
)

type progressWriter struct {
	mu     sync.Mutex
	out    io.Writer
	warned bool
}

func newProgressWriter(out io.Writer) *progressWriter {
	return &progressWriter{out: out}
}

func (w *progressWriter) WriteEvent(e partybus.Event) {
	ignoreBrokenPipe()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.warned {
		return
	}

	line, err := progressLine(e)
	if err == nil {
		_, err = fmt.Fprintln(w.out, line)
	}
	if err == nil {
		return
	}

	w.warned = true
	log.WithFields("error", err).Warn("unable to write cataloging progress; further progress output will be suppressed")
}

func progressLine(e partybus.Event) (string, error) {
	snapshot, err := parsers.ParseCatalogingProgress(e)
	if err != nil {
		return "", err
	}
	line, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	return string(line), nil
}
