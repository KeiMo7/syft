package sbomartifact

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft/sbom"
)

// memberRecord is the in-flight result of encoding one format into a staging location. Contents
// hold only the encoded bytes of a single document, and the whole manifest is never assembled in
// memory.
type memberRecord struct {
	encoder  sbom.FormatEncoder
	name     string
	path     string // staging file holding the encoded bytes
	contents []byte // populated while the index for one document is built
	size     int64
}

// stagedFile is a private, pre-created destination that an encoder writes into exactly once. It is
// created in the same filesystem as the final target so the swap-in is an atomic rename.
type stagedFile struct {
	*os.File
	path string
}

// stageDir creates a uniquely named sibling directory for building a directory target. Building
// beside the destination guarantees that commit is a rename, never a cross-device copy.
func stageDir(parent string) (string, error) {
	dir, err := os.MkdirTemp(parent, ".sbom-artifact-stage-*")
	if err != nil {
		return "", fmt.Errorf("unable to create staging directory under %q: %w", parent, err)
	}
	return dir, nil
}

// stageFile creates an empty staging file under the given staging directory with permissions no
// more permissive than a regular single-file output (0600 for members that are about to be
// renamed into place; callers adjust mode on commit).
func stageFile(dir, pattern string) (*stagedFile, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, fmt.Errorf("unable to create staging file under %q: %w", dir, err)
	}
	return &stagedFile{File: f, path: f.Name()}, nil
}

// stageSiblingFile creates a staging file next to an existing file/archive target.
func stageSiblingFile(targetPath, pattern string) (*stagedFile, error) {
	dir := filepath.Dir(targetPath)
	if err := ensureParentDir(targetPath); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, fmt.Errorf("unable to create staging file for %q: %w", targetPath, err)
	}
	if err := os.Chmod(f.Name(), 0600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("unable to set staging file permissions for %q: %w", targetPath, err)
	}
	return &stagedFile{File: f, path: f.Name()}, nil
}

// ensureParentDir creates the parent of targetPath when it is missing, and rejects the case where
// the parent path is occupied by a non-directory with an explicit error rather than the raw
// filesystem complaint.
func ensureParentDir(targetPath string) error {
	dir := filepath.Dir(targetPath)
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(dir, 0755); mkErr != nil {
				return fmt.Errorf("unable to create parent directory %q for output %q: %w", dir, targetPath, mkErr)
			}
			return nil
		}
		return fmt.Errorf("unable to inspect parent directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("parent path %q of output %q is not a directory", dir, targetPath)
	}
	return nil
}

// cleanupStage removes a staging directory; failures are swallowed because staging lives in a
// temp-style location that is also reclaimed by process/OS temp cleanup.
func cleanupStage(path string) {
	if path == "" {
		return
	}
	_ = os.RemoveAll(path)
}

// checkNoSymlink rejects destinations reached through a symlink, so an encoder can never be
// redirected outside the intended target. The final component and every intermediate component
// are checked on an absolute path: EvalSymlinks yields the real on-disk location, which must equal
// the lexical location for a symlink-free path.
func checkNoSymlink(targetPath string) error {
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("unable to resolve output path %q: %w", targetPath, err)
	}

	// the final component itself must not be a symlink
	if info, lerr := os.Lstat(absTarget); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write through symlink at output path %q", targetPath)
	}

	// the parent chain must resolve to itself (no symlinked intermediate directory)
	dir := filepath.Dir(absTarget)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("unable to resolve parent path %q: %w", dir, err)
	}
	if resolved != dir {
		return fmt.Errorf("refusing to write through a symlinked parent: %q resolves to %q outside the target path", dir, resolved)
	}
	return nil
}
