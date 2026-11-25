package sbomartifact

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// archiveEntryTime is the fixed timestamp used for every zip header so that archives built from
// the same encoded members are byte-identical. It must be a non-zero value: the archive/zip package
// treats a zero Modified field as "use the current time", which would defeat reproducibility.
var archiveEntryTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// archiveTarget writes a zip archive whose entries are the batch's shared encoded members. It does
// not encode anything itself: consuming the same staging files as the directory form guarantees
// byte-identical members across the two forms. Members are written in fixed name-sorted order
// followed by index.json.
type archiveTarget struct {
	path string
	// memberNames selects this archive's subset of the batch's shared encoded members.
	memberNames []string

	staged  *stagedFile
	writer  *zip.Writer
	existed bool
	backup  string
	swapped bool
}

func newArchiveTarget(path string, memberNames []string) *archiveTarget {
	return &archiveTarget{path: path, memberNames: memberNames}
}

func (t *archiveTarget) Path() string     { return t.path }
func (t *archiveTarget) Kind() TargetKind { return KindArchive }

// indexMembers reports the members this archive carries, used to scope its index document.
func (t *archiveTarget) indexMembers() []string { return t.memberNames }

// Stage assembles the archive from already-encoded shared members, streaming each member file
// through the zip writer without buffering the whole archive.
func (t *archiveTarget) Stage(members []*encodedMember, indexBytes []byte) error {
	if len(t.memberNames) == 0 {
		return &errEmptyTarget{path: t.path, kind: KindArchive}
	}
	if err := checkNoSymlink(t.path); err != nil {
		return err
	}
	if err := ensureParentDir(t.path); err != nil {
		return err
	}
	if info, err := os.Lstat(t.path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("output path %q exists as a directory but an archive (.zip) was requested; remove it or choose a different path", t.path)
		}
		t.existed = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("unable to inspect output archive %q: %w", t.path, err)
	}

	staged, err := stageSiblingFile(t.path, ".sbom-artifact-*.zip.tmp")
	if err != nil {
		return err
	}
	t.staged = staged
	t.writer = zip.NewWriter(staged)

	// restrict the archive to exactly this target's member selection, in fixed name-sorted order
	wanted := make(map[string]struct{}, len(t.memberNames))
	for _, name := range t.memberNames {
		wanted[name] = struct{}{}
	}
	ordered := make([]*encodedMember, 0, len(t.memberNames))
	for _, m := range members {
		if _, ok := wanted[m.name]; ok {
			ordered = append(ordered, m)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })

	for _, m := range ordered {
		if err := writeZipFile(t.writer, m.name, m.file.path); err != nil {
			return fmt.Errorf("unable to write archive entry %q in %q: %w", m.name, t.path, err)
		}
	}

	indexEntry, err := t.writer.CreateHeader(&zip.FileHeader{
		Name:     IndexName,
		Method:   zip.Deflate,
		Modified: archiveEntryTime,
	})
	if err != nil {
		return fmt.Errorf("unable to create index entry in %q: %w", t.path, err)
	}
	if _, err := indexEntry.Write(indexBytes); err != nil {
		return fmt.Errorf("unable to write index into archive %q: %w", t.path, err)
	}

	if err := t.writer.Close(); err != nil {
		return fmt.Errorf("unable to finalize archive %q: %w", t.path, err)
	}
	if err := staged.Sync(); err != nil {
		return fmt.Errorf("unable to flush staged archive %q: %w", t.path, err)
	}
	if err := staged.Close(); err != nil {
		return fmt.Errorf("unable to close staged archive %q: %w", t.path, err)
	}
	return nil
}

// writeZipFile streams one staging file into the zip under name with a deterministic header.
func writeZipFile(w *zip.Writer, name, srcPath string) error {
	entry, err := w.CreateHeader(&zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: archiveEntryTime,
	})
	if err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(entry, f)
	return err
}

func (t *archiveTarget) Commit() error {
	if t.staged == nil {
		return fmt.Errorf("internal error: commit called before successful stage for %q", t.path)
	}
	if err := os.Chmod(t.staged.path, 0644); err != nil {
		return fmt.Errorf("unable to set archive permissions for %q: %w", t.path, err)
	}
	if t.existed {
		backup, err := moveAside(t.path)
		if err != nil {
			return err
		}
		t.backup = backup
	}
	if err := os.Rename(t.staged.path, t.path); err != nil {
		if t.backup != "" {
			_ = os.Rename(t.backup, t.path)
			t.backup = ""
		}
		return fmt.Errorf("unable to replace output archive %q: %w", t.path, err)
	}
	t.staged = nil
	t.swapped = true
	return nil
}

func (t *archiveTarget) Finalize() error {
	if t.backup == "" {
		return nil
	}
	err := os.Remove(t.backup)
	t.backup = ""
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("output archive %q replaced but unable to remove previous content: %w", t.path, err)
	}
	return nil
}

func (t *archiveTarget) Rollback() error {
	if t.writer != nil {
		_ = t.writer.Close()
		t.writer = nil
	}
	if t.staged != nil {
		_ = t.staged.Close()
		_ = os.Remove(t.staged.path)
		t.staged = nil
	}
	if !t.swapped {
		return nil
	}
	if t.backup != "" {
		_ = os.Remove(t.path)
		if err := os.Rename(t.backup, t.path); err != nil {
			return fmt.Errorf("unable to restore previous output archive %q: %w", t.path, err)
		}
		t.backup = ""
	} else if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to remove rolled-back output archive %q: %w", t.path, err)
	}
	t.swapped = false
	return nil
}
