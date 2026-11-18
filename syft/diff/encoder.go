package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// OutputFormat selects how a Report is serialized.
type OutputFormat string

const (
	// JSONOutput is a single pretty-printed JSON document (paginated when requested).
	JSONOutput OutputFormat = "json"

	// JSONLOutput streams one JSON object per line: first the report header, then one
	// change per line, so reports with hundreds of thousands of components never have to
	// be rendered into a single in-memory string.
	JSONLOutput OutputFormat = "jsonl"

	// TableOutput is a human-readable, grouped text table.
	TableOutput OutputFormat = "table"
)

// Pagination controls how changes are split into pages. PageSize of zero disables
// pagination. Pages are 1-based.
type Pagination struct {
	Page     int
	PageSize int
}

// Paginate returns the requested page of changes and the 1-based page number to record
// in the report. Out-of-range pages yield an empty slice rather than an error, so
// automated paging loops terminate cleanly.
func Paginate(changes []Change, pagination Pagination) ([]Change, int) {
	if pagination.PageSize <= 0 {
		return changes, 0
	}

	page := pagination.Page
	if page < 1 {
		page = 1
	}

	start := (page - 1) * pagination.PageSize
	if start >= len(changes) {
		return []Change{}, page
	}

	end := start + pagination.PageSize
	if end > len(changes) {
		end = len(changes)
	}

	return changes[start:end], page
}

// WriteJSON writes the report as one pretty-printed JSON document.
func WriteJSON(writer io.Writer, report Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

// WriteJSONL streams the report as JSON Lines. The first line is the report header
// (everything except the changes); every subsequent line is a single change. The writer
// is flushed before returning, so callers can pass an arbitrarily large change set.
func WriteJSONL(writer io.Writer, report Report) error {
	buffered := bufio.NewWriter(writer)
	encoder := json.NewEncoder(buffered)
	encoder.SetEscapeHTML(false)

	header := report
	header.Changes = nil
	if err := encoder.Encode(header); err != nil {
		return fmt.Errorf("unable to write diff report header: %w", err)
	}

	for _, change := range report.Changes {
		if err := encoder.Encode(change); err != nil {
			return fmt.Errorf("unable to write diff change: %w", err)
		}
	}

	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("unable to flush diff report: %w", err)
	}

	return nil
}
