//go:build windows

package sbomartifact

import (
	"context"
	"os"
)

// windowsLock relies on the exclusive create/open semantics of the lock file itself. Windows
// cannot take a POSIX flock, so acquisition is attempted with O_CREATE|O_EXCL and holders poll
// until the file is released; the file is always removed on unlock, and a crashed writer leaves a
// stale file that the next acquire attempts to claim after one failed open.
type windowsLock struct {
	fileLock
}

func newPlatformLock(lockPath string, f *os.File) Locker {
	// the shared opener's handle is not the exclusive handle on Windows
	_ = f.Close()
	return &windowsLock{fileLock: fileLock{path: lockPath}}
}

func (l *windowsLock) Lock(ctx context.Context) error {
	return waitLock(ctx, func() error {
		f, err := os.OpenFile(l.path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		l.f = f
		return nil
	})
}

func (l *windowsLock) Unlock() error {
	return l.fileLock.unlock(true)
}

func (l *windowsLock) RemoveFile() error { return l.fileLock.removeLockFile() }
