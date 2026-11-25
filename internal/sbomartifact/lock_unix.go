//go:build !windows

package sbomartifact

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

// unixLock serializes writers with an advisory flock on a lock file. flock is per open file
// description and is released automatically by the kernel if the process is killed, so a crashed
// writer never leaves a permanently held lock behind.
type unixLock struct {
	fileLock
}

func newPlatformLock(lockPath string, f *os.File) Locker {
	return &unixLock{fileLock: fileLock{path: lockPath, f: f}}
}

func (l *unixLock) Lock(ctx context.Context) error {
	return waitLock(ctx, func() error {
		return unix.Flock(int(l.f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	})
}

func (l *unixLock) Unlock() error {
	// drop the kernel lock before closing; removal of the lock file is best-effort here and can be
	// retried through RemoveFile (e.g. after a read-only parent directory becomes writable again).
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.fileLock.unlock(true)
}

func (l *unixLock) RemoveFile() error { return l.fileLock.removeLockFile() }
