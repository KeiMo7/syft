package sbomartifact

import (
	"fmt"
	"io"
	"os"
)

// fileTarget writes one shared encoded member to a single file, preserving the historical
// single-file byte output while gaining atomic visibility: the member's staging file is copied to
// a sibling temp destination (hardlinked where the filesystem allows it) and renamed over the
// destination only after a successful stage.
type fileTarget struct {
	path string
	// memberName selects which of the batch's encoded members this target carries; grouping
	// guarantees exactly one encoder for a file destination.
	memberName string

	stagedPath string
	existed    bool
	backup     string
	swapped    bool
}

func newFileTarget(path, memberName string) *fileTarget {
	return &fileTarget{path: path, memberName: memberName}
}

func (t *fileTarget) Path() string     { return t.path }
func (t *fileTarget) Kind() TargetKind { return KindFile }

func (t *fileTarget) Stage(members []*encodedMember, _ []byte) error {
	member := findMember(members, t.memberName)
	if member == nil {
		return fmt.Errorf("internal error: member %q missing for file target %q", t.memberName, t.path)
	}
	if err := checkNoSymlink(t.path); err != nil {
		return err
	}
	if err := ensureParentDir(t.path); err != nil {
		return err
	}
	if _, err := os.Lstat(t.path); err == nil {
		t.existed = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("unable to inspect output file %q: %w", t.path, err)
	}

	staged, err := stageSiblingFile(t.path, ".sbom-artifact-*")
	if err != nil {
		return err
	}
	t.stagedPath = staged.path
	if err := staged.Close(); err != nil {
		_ = os.Remove(t.stagedPath)
		return fmt.Errorf("unable to prepare staged output for %q: %w", t.path, err)
	}

	// prefer a hard link: it makes the stage an O(1) link with identical bytes and no extra disk
	// copy; fall back to a streamed copy on filesystems that reject cross-directory links.
	if err := os.Link(member.file.path, t.stagedPath); err != nil {
		if copyErr := copyFileContents(member.file.path, t.stagedPath); copyErr != nil {
			_ = os.Remove(t.stagedPath)
			return fmt.Errorf("unable to stage output file %q: %w", t.path, copyErr)
		}
	}
	return nil
}

func (t *fileTarget) Commit() error {
	if t.stagedPath == "" {
		return fmt.Errorf("internal error: commit called before successful stage for %q", t.path)
	}
	if err := os.Chmod(t.stagedPath, 0644); err != nil {
		return fmt.Errorf("unable to set output file permissions for %q: %w", t.path, err)
	}
	if t.existed {
		backup, err := moveAside(t.path)
		if err != nil {
			return err
		}
		t.backup = backup
	}
	if err := os.Rename(t.stagedPath, t.path); err != nil {
		if t.backup != "" {
			_ = os.Rename(t.backup, t.path)
			t.backup = ""
		}
		return fmt.Errorf("unable to replace output file %q: %w", t.path, err)
	}
	t.stagedPath = ""
	t.swapped = true
	return nil
}

func (t *fileTarget) Finalize() error {
	if t.backup == "" {
		return nil
	}
	err := os.Remove(t.backup)
	t.backup = ""
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("output file %q replaced but unable to remove previous content: %w", t.path, err)
	}
	return nil
}

func (t *fileTarget) Rollback() error {
	if t.stagedPath != "" {
		_ = os.Remove(t.stagedPath)
		t.stagedPath = ""
	}
	if !t.swapped {
		return nil
	}
	if t.backup != "" {
		_ = os.Remove(t.path)
		if err := os.Rename(t.backup, t.path); err != nil {
			return fmt.Errorf("unable to restore previous output file %q: %w", t.path, err)
		}
		t.backup = ""
	} else if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to remove rolled-back output file %q: %w", t.path, err)
	}
	t.swapped = false
	return nil
}

func findMember(members []*encodedMember, name string) *encodedMember {
	for _, m := range members {
		if m.name == name {
			return m
		}
	}
	return nil
}

// copyFileContents streams src into dst (which must already exist) without buffering the document.
func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
