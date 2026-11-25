package sbomartifact

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// directoryTarget materializes the batch's shared encoded members inside a directory, plus an
// index.json cataloging them. The whole tree is built in a private sibling staging directory by
// hard-linking (or streaming-copying) each encoded member into place, then swapped in atomically;
// a pre-existing directory is moved aside rather than deleted first.
type directoryTarget struct {
	path string
	// memberNames selects this target's subset of the batch's shared encoded members.
	memberNames []string

	stagePath string
	existed   bool
	backup    string
	swapped   bool
}

func newDirectoryTarget(path string, memberNames []string) *directoryTarget {
	return &directoryTarget{path: path, memberNames: memberNames}
}

func (t *directoryTarget) Path() string     { return t.path }
func (t *directoryTarget) Kind() TargetKind { return KindDirectory }

// indexMembers reports the members this directory carries, used to scope its index document.
func (t *directoryTarget) indexMembers() []string { return t.memberNames }

func (t *directoryTarget) Stage(members []*encodedMember, indexBytes []byte) error {
	if len(t.memberNames) == 0 {
		return &errEmptyTarget{path: t.path, kind: KindDirectory}
	}
	if err := checkNoSymlink(t.path); err != nil {
		return err
	}
	if err := ensureParentDir(t.path); err != nil {
		return err
	}
	if info, err := os.Lstat(t.path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output path %q exists as a file but a directory bundle was requested; remove it or choose a different path", t.path)
		}
		t.existed = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("unable to inspect output directory %q: %w", t.path, err)
	}

	stage, err := stageDir(filepath.Dir(t.path))
	if err != nil {
		return err
	}
	t.stagePath = stage

	names := make(map[string]struct{}, len(t.memberNames))
	for _, name := range t.memberNames {
		if _, dup := names[name]; dup {
			return fmt.Errorf("duplicate member name %q in target %q", name, t.path)
		}
		names[name] = struct{}{}

		member := findMember(members, name)
		if member == nil {
			return fmt.Errorf("internal error: member %q missing for directory target %q", name, t.path)
		}

		finalStaged := filepath.Join(stage, name)
		// hard link gives byte-identical members for free; fall back to a copy when the staging
		// member and this target live on filesystems that cannot share an inode
		if err := os.Link(member.file.path, finalStaged); err != nil {
			if copyErr := copyFileContents(member.file.path, finalStaged); copyErr != nil {
				return fmt.Errorf("unable to stage member %q in target %q: %w", name, t.path, copyErr)
			}
		}
		if err := os.Chmod(finalStaged, 0644); err != nil {
			return fmt.Errorf("unable to set member permissions for %q: %w", finalStaged, err)
		}
	}

	indexPath := filepath.Join(stage, IndexName)
	if err := writeFileAtomicInDir(stage, indexPath, indexBytes, 0644); err != nil {
		return fmt.Errorf("unable to write index for target %q: %w", t.path, err)
	}
	return nil
}

// writeFileAtomicInDir writes data to finalPath via a temp file in the same directory and renames
// it into place, so even the index never appears truncated.
func writeFileAtomicInDir(dir, finalPath string, data []byte, mode os.FileMode) error {
	f, err := stageFile(dir, "index-*")
	if err != nil {
		return err
	}
	if _, err := io.Writer(f).Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(f.path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.path)
		return err
	}
	if err := os.Chmod(f.path, mode); err != nil {
		_ = os.Remove(f.path)
		return err
	}
	return os.Rename(f.path, finalPath)
}

func (t *directoryTarget) Commit() error {
	if t.stagePath == "" {
		return fmt.Errorf("internal error: commit called before successful stage for %q", t.path)
	}
	if err := os.Chmod(t.stagePath, 0755); err != nil {
		return fmt.Errorf("unable to set directory permissions for %q: %w", t.path, err)
	}

	if t.existed {
		backup, err := moveAside(t.path)
		if err != nil {
			return err
		}
		t.backup = backup
	}

	if err := os.Rename(t.stagePath, t.path); err != nil {
		if t.backup != "" {
			_ = os.Rename(t.backup, t.path)
			t.backup = ""
		}
		return fmt.Errorf("unable to replace output directory %q: %w", t.path, err)
	}
	t.stagePath = ""
	t.swapped = true
	return nil
}

func (t *directoryTarget) Finalize() error {
	if t.backup == "" {
		return nil
	}
	err := os.RemoveAll(t.backup)
	t.backup = ""
	if err != nil {
		return fmt.Errorf("output directory %q replaced but unable to remove previous content: %w", t.path, err)
	}
	return nil
}

func (t *directoryTarget) Rollback() error {
	if t.stagePath != "" && !t.swapped {
		cleanupStage(t.stagePath)
		t.stagePath = ""
	}
	if !t.swapped {
		return nil
	}
	if t.backup != "" {
		_ = os.RemoveAll(t.path)
		if err := os.Rename(t.backup, t.path); err != nil {
			return fmt.Errorf("unable to restore previous output directory %q: %w", t.path, err)
		}
		t.backup = ""
	} else if t.existed {
		return fmt.Errorf("cannot restore output directory %q: backup missing", t.path)
	} else {
		if err := os.RemoveAll(t.path); err != nil {
			return fmt.Errorf("unable to remove rolled-back output directory %q: %w", t.path, err)
		}
	}
	t.swapped = false
	return nil
}

// moveAside relocates an existing destination to a unique sibling path and returns that path. The
// rename is atomic, so the old content stays fully visible until the new tree is ready.
func moveAside(path string) (string, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	for i := 0; ; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf(".%s.backup-%d", base, i))
		if _, err := os.Lstat(candidate); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("unable to inspect backup path %q: %w", candidate, err)
		}
		if err := os.Rename(path, candidate); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("unable to move existing output %q aside: %w", path, err)
		}
		return candidate, nil
	}
}
