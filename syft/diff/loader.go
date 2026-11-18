package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// LoadedInput bundles a decoded SBOM with the provenance information the diff report
// preserves.
type LoadedInput struct {
	SBOM    sbom.SBOM
	Input   InputDescription
	rawData []byte
}

// LoadSBOM reads and decodes an SBOM from path, or from reader when path is "-". The
// whole document is buffered in memory (the diff itself is an in-memory operation and
// never asks the caller to spill inputs to disk first). Parse failures are returned as
// LoadError values carrying the concrete document position.
func LoadSBOM(path string, reader io.Reader) (*LoadedInput, error) {
	if path == "" {
		path = "-"
	}

	data, err := readAll(path, reader)
	if err != nil {
		return nil, err
	}

	decoded, formatID, schemaVersion, err := format.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, parseLoadError(path, data, err)
	}
	if decoded == nil {
		return nil, &LoadError{Path: path, Stage: "parse", Offset: -1, Err: fmt.Errorf("no SBOM produced from input")}
	}

	input := describeInput(path, data, decoded, formatID, schemaVersion)

	return &LoadedInput{
		SBOM:    *decoded,
		Input:   input,
		rawData: data,
	}, nil
}

// CheckSchemaCompatibility refuses diffs across different (format, schema version) pairs
// and reports exactly which two versions were seen.
func CheckSchemaCompatibility(oldInput, newInput InputDescription) error {
	if oldInput.FormatID != newInput.FormatID || oldInput.SchemaVersion != newInput.SchemaVersion {
		return &SchemaMismatchError{
			OldFormat: oldInput.FormatID,
			OldSchema: oldInput.SchemaVersion,
			NewFormat: newInput.FormatID,
			NewSchema: newInput.SchemaVersion,
		}
	}
	return nil
}

func readAll(path string, reader io.Reader) ([]byte, error) {
	if path != "-" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, &LoadError{Path: path, Stage: "read", Offset: -1, Err: err}
		}
		return data, nil
	}

	if reader == nil {
		return nil, &LoadError{Path: path, Stage: "read", Offset: -1, Err: fmt.Errorf("no reader provided for STDIN")}
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, &LoadError{Path: path, Stage: "read", Offset: -1, Err: err}
	}
	return data, nil
}

func parseLoadError(path string, data []byte, err error) error {
	loadErr := &LoadError{Path: path, Stage: "parse", Offset: -1}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		loadErr.Offset = syntaxErr.Offset
		loadErr.Line, loadErr.Column = lineColumn(data, syntaxErr.Offset)
		loadErr.Err = syntaxErr
		return loadErr
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		loadErr.Offset = typeErr.Offset
		loadErr.Line, loadErr.Column = lineColumn(data, typeErr.Offset)
		loadErr.Err = typeErr
		return loadErr
	}

	loadErr.Err = err
	return loadErr
}

// lineColumn converts a byte offset into the 1-based line and column within the document.
func lineColumn(data []byte, offset int64) (int, int) {
	if offset <= 0 {
		return 0, 0
	}

	position := int(offset)
	if position > len(data) {
		position = len(data)
	}

	line := 1
	column := 1
	for _, b := range data[:position] {
		if b == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}

	return line, column
}

func describeInput(path string, data []byte, decoded *sbom.SBOM, formatID sbom.FormatID, schemaVersion string) InputDescription {
	description := InputDescription{
		Path:          path,
		FormatID:      string(formatID),
		SchemaVersion: schemaVersion,
	}

	if decoded.Artifacts.Packages != nil {
		description.ComponentCount = decoded.Artifacts.Packages.PackageCount()
	}

	description.SourceType, description.SourceName, description.SourceVersion = sourceInfo(decoded.Source)
	description.GeneratedAt = generatedAt(path, data, decoded)

	return description
}

func sourceInfo(description source.Description) (sourceType, name, version string) {
	name = description.Name
	version = description.Version

	switch description.Metadata.(type) {
	case source.ImageMetadata, *source.ImageMetadata:
		sourceType = "image"
	case source.DirectoryMetadata, *source.DirectoryMetadata:
		sourceType = "directory"
	case source.FileMetadata, *source.FileMetadata:
		sourceType = "file"
	default:
		sourceType = genericSourceType(description)
	}

	return sourceType, name, version
}

func genericSourceType(description source.Description) string {
	// SPDX/CycloneDX decoders may leave metadata in a format-neutral shape; fall back to
	// the name/version fields rather than claiming an unknown source type.
	if description.Name == "" && description.Version == "" {
		return ""
	}
	return "unknown"
}

func generatedAt(path string, data []byte, decoded *sbom.SBOM) *string {
	if timestamp := documentTimestamp(data); timestamp != "" {
		return &timestamp
	}

	if path != "-" {
		if info, err := os.Stat(path); err == nil {
			modTime := info.ModTime().UTC().Format(time.RFC3339)
			return &modTime
		}
	}

	_ = decoded
	return nil
}

// documentTimestamp extracts a generation timestamp from the small set of conventional
// top-level fields used by the supported SBOM formats without fully re-decoding the
// document into format-specific structs.
func documentTimestamp(data []byte) string {
	var probe struct {
		Descriptor *struct {
			Timestamp string `json:"timestamp"`
		} `json:"descriptor"`
		CreationInfo *struct {
			Created string `json:"created"`
		} `json:"creationInfo"`
		Metadata *struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal(data, &probe); err != nil {
		return ""
	}

	switch {
	case probe.Descriptor != nil && probe.Descriptor.Timestamp != "":
		return probe.Descriptor.Timestamp
	case probe.CreationInfo != nil && probe.CreationInfo.Created != "":
		return probe.CreationInfo.Created
	case probe.Metadata != nil && probe.Metadata.Timestamp != "":
		return probe.Metadata.Timestamp
	default:
		return ""
	}
}
