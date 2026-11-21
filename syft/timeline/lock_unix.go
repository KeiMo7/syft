//go:build !windows

package timeline

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// acquireLock takes an exclusive advisory lock on path, creating the file when needed. It blocks
// until the lock is available, so two concurrent writers serialize rather than interleave.
func acquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("unable to open lock file %q: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unable to lock %q: %w", path, err)
	}

	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
