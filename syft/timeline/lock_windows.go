//go:build windows

package timeline

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// acquireLock takes an exclusive lock on path, creating the file when needed. It blocks until the
// lock is available, so two concurrent writers serialize rather than interleave.
func acquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("unable to open lock file %q: %w", path, err)
	}

	handle := windows.Handle(f.Fd())
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unable to lock %q: %w", path, err)
	}

	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
		_ = f.Close()
	}, nil
}
