package diff

import "fmt"

// LoadError wraps a failure while reading or parsing one SBOM input. It carries the
// input path and, when the underlying parser could locate the problem, the byte offset
// and line/column of the failure, so callers never have to report only an overall
// "parse failed" message.
type LoadError struct {
	// Path is the input the failure relates to ("-" for STDIN).
	Path string

	// Stage describes where the failure happened: "read" or "parse".
	Stage string

	// Offset is the zero-based byte offset the parser reported, when known.
	Offset int64

	// Line and Column are the 1-based document position the parser reported, when known.
	Line   int
	Column int

	Err error
}

func (e *LoadError) Error() string {
	switch {
	case e.Line > 0:
		return fmt.Sprintf("SBOM %s failure for %q at line %d column %d (byte offset %d): %v",
			e.Stage, e.Path, e.Line, e.Column, e.Offset, e.Err)
	case e.Offset >= 0:
		return fmt.Sprintf("SBOM %s failure for %q at byte offset %d: %v",
			e.Stage, e.Path, e.Offset, e.Err)
	default:
		return fmt.Sprintf("SBOM %s failure for %q: %v", e.Stage, e.Path, e.Err)
	}
}

func (e *LoadError) Unwrap() error {
	return e.Err
}

// SchemaMismatchError reports that the two inputs declare incompatible schemas. The diff
// is refused rather than silently comparing documents with different shapes.
type SchemaMismatchError struct {
	OldFormat string
	OldSchema string
	NewFormat string
	NewSchema string
}

func (e *SchemaMismatchError) Error() string {
	return fmt.Sprintf(
		"refusing to diff SBOMs with different schema versions: old=%s/%s new=%s/%s",
		e.OldFormat, e.OldSchema, e.NewFormat, e.NewSchema,
	)
}
