package sbomartifact

import (
	"fmt"
	"io"
	"os"
)

// CopyFileAtomic copies the contents of src into dst using the same staging-and-rename guarantees
// as an encoded single-file target: dst never appears truncated, a pre-existing dst is moved aside
// rather than deleted, and a failure leaves the previous dst intact. The bytes written are read
// straight from src through a single stream — the document is never fully buffered here.
//
// It backs the convert command's exact-format passthrough optimization, whose on-disk byte result
// must stay identical to a plain file copy while gaining the batch's atomicity properties.
func CopyFileAtomic(src io.ReadSeekCloser, dst string) (err error) {
	if err := checkNoSymlink(dst); err != nil {
		return err
	}
	if err := ensureParentDir(dst); err != nil {
		return err
	}

	existed := false
	if _, statErr := os.Lstat(dst); statErr == nil {
		existed = true
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("unable to inspect output file %q: %w", dst, statErr)
	}

	staged, err := stageSiblingFile(dst, ".sbom-artifact-copy-*")
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = staged.Close()
		_ = os.Remove(staged.path)
	}

	if _, err := io.Copy(staged, src); err != nil {
		cleanup()
		return fmt.Errorf("unable to write report file %q: %w", dst, err)
	}
	if err := staged.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("unable to flush report file %q: %w", dst, err)
	}
	if err := staged.Close(); err != nil {
		cleanup()
		return fmt.Errorf("unable to finalize report file %q: %w", dst, err)
	}

	if err := os.Chmod(staged.path, 0644); err != nil {
		_ = os.Remove(staged.path)
		return fmt.Errorf("unable to set output file permissions for %q: %w", dst, err)
	}

	var backup string
	if existed {
		backup, err = moveAside(dst)
		if err != nil {
			_ = os.Remove(staged.path)
			return err
		}
	}
	if err := os.Rename(staged.path, dst); err != nil {
		if backup != "" {
			_ = os.Rename(backup, dst)
		} else {
			_ = os.Remove(staged.path)
		}
		return fmt.Errorf("unable to replace output file %q: %w", dst, err)
	}
	if backup != "" {
		if rmErr := os.Remove(backup); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("output file %q replaced but unable to remove previous content: %w", dst, rmErr)
		}
	}
	return nil
}
