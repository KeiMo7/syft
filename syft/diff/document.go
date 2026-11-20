package diff

import (
	"errors"
	"fmt"
	"io"

	"github.com/Masterminds/semver/v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
)

// Distinguishable failure modes for reading a document. Callers (and users) need to tell a
// missing file, an unrecognized format, a corrupt document, and an incompatible tool version
// apart — none of them may silently degrade into "everything is newly added".
var (
	// ErrFormatNotIdentified means no decoder recognized the document.
	ErrFormatNotIdentified = errors.New("SBOM format not recognized")

	// ErrCorruptDocument means the document was identified but could not be decoded.
	ErrCorruptDocument = errors.New("SBOM document could not be decoded (file may be corrupt)")

	// ErrIncompatibleSchema means the document was written by a tool version whose schema
	// this version of syft cannot read.
	ErrIncompatibleSchema = errors.New("SBOM schema version is newer than this syft supports")
)

// Document is the comparable view of one SBOM: its provenance (tool, format, schema) plus the
// stable identity of every package it records.
type Document struct {
	Format        string
	SchemaVersion string
	ToolName      string
	ToolVersion   string
	SourceName    string
	Records       []Record
}

// ReadDocument extracts the comparable view of an SBOM from the given reader. syft-json
// documents are streamed (never fully materialized); other recognized formats are decoded one
// document at a time and immediately reduced to records, so two full SBOMs are never held in
// memory at once.
func ReadDocument(r io.ReadSeeker) (*Document, error) {
	id, _ := format.Identify(r)
	if id == "" {
		return nil, ErrFormatNotIdentified
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to start of SBOM: %w", err)
	}

	if id == syftjson.ID {
		doc, err := readSyftJSONStream(r)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorruptDocument, err)
		}
		if err := checkSchemaSupported(doc.SchemaVersion); err != nil {
			return nil, err
		}
		return doc, nil
	}

	// fallback: decode through the format machinery, then reduce to records and let the full
	// SBOM be garbage collected before the caller reads the second document
	s, formatID, version, err := format.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptDocument, err)
	}
	if s == nil {
		return nil, fmt.Errorf("%w: no SBOM produced", ErrCorruptDocument)
	}

	doc := &Document{
		Format:        string(formatID),
		SchemaVersion: version,
		ToolName:      s.Descriptor.Name,
		ToolVersion:   s.Descriptor.Version,
		SourceName:    s.Source.Name,
	}
	if doc.SourceName == "" {
		doc.SourceName = s.Source.ID
	}
	for _, p := range s.Artifacts.Packages.Sorted() {
		doc.Records = append(doc.Records, RecordFromPackage(p))
	}
	return doc, nil
}

// checkSchemaSupported refuses syft-json documents written by a newer tool than this one,
// with an actionable message, rather than risking a silently misread baseline.
func checkSchemaSupported(documentVersion string) error {
	documentV, err := semver.NewVersion(documentVersion)
	if err != nil {
		return fmt.Errorf("%w: unable to parse document schema version %q", ErrIncompatibleSchema, documentVersion)
	}
	parserV, err := semver.NewVersion(internal.JSONSchemaVersion)
	if err != nil {
		return nil // cannot judge our own version; proceed
	}
	if documentV.GreaterThan(parserV) {
		return fmt.Errorf("%w: document schema is %s but this syft understands at most %s; regenerate the baseline with an older syft or upgrade this syft", ErrIncompatibleSchema, documentVersion, internal.JSONSchemaVersion)
	}
	return nil
}
