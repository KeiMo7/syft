package incremental

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Masterminds/semver/v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

var (
	// ErrBaselineMissing indicates that no reference SBOM was available.
	ErrBaselineMissing = errors.New("incremental reference SBOM is missing")

	// ErrBaselineCorrupt indicates that the reference SBOM could not be decoded
	// or is structurally incomplete.
	ErrBaselineCorrupt = errors.New("incremental reference SBOM is corrupt")

	// ErrUnsupportedBaseline indicates that the reference format or schema
	// version cannot be used for incremental processing.
	ErrUnsupportedBaseline = errors.New("incremental reference SBOM format is not supported")

	// ErrBaselineIncomplete indicates that the document is a resume checkpoint,
	// not a complete SBOM. Use LoadCheckpoint to resume from it.
	ErrBaselineIncomplete = errors.New("incremental reference SBOM is incomplete")
)

// Baseline is a decoded reference SBOM.
type Baseline struct {
	SBOM          *sbom.SBOM
	FormatID      sbom.FormatID
	FormatVersion string
	Path          string
	Complete      bool
}

// LoadBaseline loads a reference SBOM. Only syft-json documents whose schema is
// known to this Syft version are accepted. Callers should treat any error as a
// request to fall back to a full scan, not as a fatal cataloging error.
func LoadBaseline(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBaselineMissing, path)
		}
		return nil, fmt.Errorf("%w: unable to open %s: %v", ErrBaselineCorrupt, path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	baseline, err := DecodeBaseline(f)
	if err != nil {
		return nil, err
	}
	baseline.Path = path
	return baseline, nil
}

// DecodeBaseline decodes a reference SBOM from a reader.
func DecodeBaseline(reader io.Reader) (*Baseline, error) {
	return decodeBaseline(reader, false)
}

// LoadCheckpoint loads a checkpoint written by WriteCheckpointAtomic. Complete
// and incomplete checkpoints are both accepted; callers should consult
// Baseline.Complete before using one as a final audit artifact.
func LoadCheckpoint(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBaselineMissing, path)
		}
		return nil, fmt.Errorf("%w: unable to open %s: %v", ErrBaselineCorrupt, path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	baseline, err := decodeBaseline(f, true)
	if err != nil {
		return nil, err
	}
	baseline.Path = path
	return baseline, nil
}

func decodeBaseline(reader io.Reader, allowIncomplete bool) (*Baseline, error) {
	decoded, formatID, formatVersion, err := format.Decode(reader)
	if err != nil {
		if formatID != "" {
			return nil, fmt.Errorf("%w: format=%s version=%s: %v", ErrUnsupportedBaseline, formatID, formatVersion, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrBaselineCorrupt, err)
	}
	if formatID != syftjson.ID {
		return nil, fmt.Errorf("%w: found format %q; incremental baselines must use syft-json", ErrUnsupportedBaseline, formatID)
	}
	if err := supportedSchemaVersion(formatVersion); err != nil {
		return nil, err
	}
	if decoded == nil || decoded.Artifacts.Packages == nil {
		return nil, fmt.Errorf("%w: decoded document has no package collection", ErrBaselineCorrupt)
	}
	complete, hasMarker := checkpointCompleteness(decoded)
	if hasMarker && !complete && !allowIncomplete {
		return nil, fmt.Errorf("%w: use LoadCheckpoint to resume from this file", ErrBaselineIncomplete)
	}

	return &Baseline{
		SBOM:          decoded,
		FormatID:      formatID,
		FormatVersion: formatVersion,
		Complete:      !hasMarker || complete,
	}, nil
}

func supportedSchemaVersion(version string) error {
	documentVersion, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("%w: invalid schema version %q: %v", ErrUnsupportedBaseline, version, err)
	}
	parserVersion, err := semver.NewVersion(internal.JSONSchemaVersion)
	if err != nil {
		return fmt.Errorf("%w: invalid parser schema version %q: %v", ErrUnsupportedBaseline, internal.JSONSchemaVersion, err)
	}
	if documentVersion.GreaterThan(parserVersion) {
		return fmt.Errorf("%w: document schema %s is newer than supported schema %s", ErrUnsupportedBaseline, version, internal.JSONSchemaVersion)
	}
	return nil
}

// WriteAtomic writes a complete SBOM to path using the existing syft-json
// serializer. A temporary file in the same directory is synced and renamed over
// the destination only after encoding succeeds, so an interrupted run cannot
// leave a partial document at the final path.
func WriteAtomic(path string, document *sbom.SBOM) (err error) {
	if document == nil {
		return fmt.Errorf("cannot write a nil SBOM")
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".partial-*")
	if err != nil {
		return fmt.Errorf("unable to create temporary SBOM: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()

	encoder, err := syftjson.NewFormatEncoderWithConfig(syftjson.EncoderConfig{Pretty: true})
	if err != nil {
		_ = temp.Close()
		return err
	}
	if err = encoder.Encode(temp, *document); err != nil {
		_ = temp.Close()
		return fmt.Errorf("unable to encode SBOM: %w", err)
	}
	if err = temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("unable to sync SBOM: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("unable to close SBOM: %w", err)
	}
	if err = os.Chmod(tempPath, 0o644); err != nil {
		return fmt.Errorf("unable to set SBOM permissions: %w", err)
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("unable to publish SBOM: %w", err)
	}

	if dirHandle, openErr := os.Open(dir); openErr == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

// WriteCheckpointAtomic writes a resumable checkpoint using syft-json. The
// completeness marker lives in the existing descriptor configuration section,
// so the document remains a normal syft-json SBOM while incomplete checkpoints
// are rejected by LoadBaseline.
func WriteCheckpointAtomic(path string, document *sbom.SBOM, complete bool, processedPaths []string) error {
	if document == nil {
		return fmt.Errorf("cannot write a nil SBOM checkpoint")
	}

	configuration, err := configurationMap(document.Descriptor.Configuration)
	if err != nil {
		return err
	}
	paths := append([]string(nil), processedPaths...)
	sort.Strings(paths)
	configuration["incremental"] = map[string]any{
		"version":        1,
		"complete":       complete,
		"processedPaths": paths,
	}

	checkpoint := *document
	checkpoint.Descriptor.Configuration = configuration
	return WriteAtomic(path, &checkpoint)
}

func checkpointCompleteness(document *sbom.SBOM) (bool, bool) {
	configuration, err := configurationMap(document.Descriptor.Configuration)
	if err != nil {
		return false, false
	}
	raw, exists := configuration["incremental"]
	if !exists {
		return false, false
	}
	values, ok := raw.(map[string]any)
	if !ok {
		return false, false
	}
	complete, ok := values["complete"].(bool)
	if !ok {
		return false, false
	}
	return complete, true
}

func configurationMap(configuration any) (map[string]any, error) {
	if configuration == nil {
		return make(map[string]any), nil
	}

	encoded, err := json.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("unable to encode descriptor configuration: %w", err)
	}
	var values map[string]any
	if err := json.Unmarshal(encoded, &values); err != nil {
		return nil, fmt.Errorf("unable to read descriptor configuration: %w", err)
	}
	if values == nil {
		values = make(map[string]any)
	}
	return values, nil
}
