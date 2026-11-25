// Package sbomartifact persists a single SBOM, encoded in one or more formats, as a coherent
// on-disk artifact: an individual file, a directory of format documents plus an index, or an
// archive containing the same members as the directory form. All targets are built in private
// staging locations and swapped into place atomically, so an observer never sees partial output
// and a failed batch leaves pre-existing content untouched.
package sbomartifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/sbom"
)

// TargetKind describes how an output destination is materialized on disk.
type TargetKind int

const (
	// KindFile writes a single encoded document to a single file.
	KindFile TargetKind = iota
	// KindDirectory writes one document per requested format into a directory, together with an index.
	KindDirectory
	// KindArchive writes the same member set as the directory form into a zip archive.
	KindArchive
)

func (k TargetKind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindDirectory:
		return "directory"
	case KindArchive:
		return "archive"
	default:
		return "unknown"
	}
}

// archiveExtensions are the suffixes that identify a not-yet-existing destination as an archive.
var archiveExtensions = []string{".zip", ".sbom.zip"}

// ClassifyPath determines the target kind for a destination path. An existing directory is always
// a directory target and an existing regular file is always a file target; a missing destination
// is classified by its suffix so users can seed either form by path alone.
//
// Type mismatches (for example an archive suffix on an existing directory) are reported as
// explicit, user-facing errors instead of leaking the filesystem's own "is a directory" message.
func ClassifyPath(path string) (TargetKind, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return 0, fmt.Errorf("unable to inspect output path %q: %w", path, err)
		}
		if isArchivePath(path) {
			return KindArchive, nil
		}
		return KindFile, nil
	}

	if info.Mode()&os.ModeSymlink != 0 {
		// resolve the link target so classification follows the same rules as writing does
		resolved, rerr := filepath.EvalSymlinks(path)
		if rerr != nil {
			return 0, fmt.Errorf("unable to resolve output path %q: %w", path, rerr)
		}
		return ClassifyPath(resolved)
	}

	if info.IsDir() {
		if isArchivePath(path) {
			return 0, fmt.Errorf("output path %q already exists as a directory but the .zip suffix requests an archive; remove it or choose a different path", path)
		}
		return KindDirectory, nil
	}

	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("output path %q exists but is neither a regular file nor a directory", path)
	}
	if isArchivePath(path) {
		return KindArchive, nil
	}
	return KindFile, nil
}

// classifyForEncoders resolves the kind of a destination in the context of the formats it will
// carry. Existing on-disk type always wins; for a missing path an archive suffix means archive,
// more than one format means a directory bundle, and a single format means a single file. This
// lets one request create a multi-document bundle at a directory path without a pre-existing
// directory, while keeping single-file behavior byte-for-byte compatible.
func classifyForEncoders(path string, encoders []sbom.FormatEncoder) (TargetKind, error) {
	kind, err := ClassifyPath(path)
	if err != nil {
		return 0, err
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		// an existing destination's type is authoritative
		return kind, nil
	} else if !os.IsNotExist(statErr) {
		return 0, fmt.Errorf("unable to inspect output path %q: %w", path, statErr)
	}
	// missing destination: infer directory intent from multiple formats
	if kind == KindFile && len(encoders) > 1 {
		return KindDirectory, nil
	}
	return kind, nil
}

func isArchivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range archiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
