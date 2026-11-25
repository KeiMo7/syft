package sbomartifact

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Locker serializes writers that target the same destination. Two concurrent writes to the same
// path are serialized by the OS so the visible result is always one writer's complete artifact,
// never an interleaving of two builds.
type Locker interface {
	// Lock blocks until the lock is acquired, ctx is canceled, or the attempt times out.
	Lock(ctx context.Context) error
	// Unlock releases the OS lock and removes the lock file when possible. A removal failure (for
	// example a read-only parent directory) is returned so the caller can retry via RemoveFile once
	// the obstruction clears; the OS lock itself is always released.
	Unlock() error
	// RemoveFile retries removal of a lock file left behind by an unsuccessful Unlock.
	RemoveFile() error
}

// lockTimeout bounds how long a writer waits behind another writer that holds the same target. It
// is generous enough to cover a large multi-format encode but still turns a wedged holder into a
// reported error instead of an indefinite hang.
const lockTimeout = 30 * time.Second

// lockPollInterval is the retry cadence while waiting on a held lock.
const lockPollInterval = 50 * time.Millisecond

// fileLock is the common state shared by the platform-specific locking primitives.
type fileLock struct {
	path     string
	f        *os.File
	released bool
}

// lockTarget creates (but does not acquire) a Locker for the given destination path. The lock file
// always sits beside the destination so that locking does not require write access anywhere else.
func lockTarget(targetPath string) (Locker, error) {
	lockPath := lockPathFor(targetPath)
	// MkdirAll is a no-op when the parent already exists; it covers archive and file targets whose
	// parent directory has not been created yet.
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return nil, fmt.Errorf("unable to prepare lock for output %q: %w", targetPath, err)
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("unable to open lock for output %q: %w", targetPath, err)
	}
	return newPlatformLock(lockPath, f), nil
}

// lockPathFor derives the lock file path from a destination. The lock always sits in the
// destination's parent directory (never inside a directory target itself), so locking still works
// when the target is read-only and a crashed holder never leaves a lock inside user content.
func lockPathFor(targetPath string) string {
	return filepath.Join(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".lock")
}

func (l *fileLock) unlock(removeFile bool) error {
	if l.released && l.f == nil {
		// fully released on a prior call; nothing left to do (idempotent)
		return nil
	}
	var errs error
	if l.f != nil {
		if err := l.f.Close(); err != nil && !os.IsNotExist(err) {
			errs = joinErr(errs, err)
		}
		l.f = nil
	}
	l.released = true
	if removeFile {
		// when removal fails the lock stays on disk but its handle is closed; a retained caller can
		// retry removal through removeLockFile once permissions allow it
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
			errs = joinErr(errs, err)
		}
	}
	return errs
}

// removeLockFile retries deletion of a lock file whose earlier removal was blocked.
func (l *fileLock) removeLockFile() error {
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// waitLock polls tryLock until it succeeds, the context is canceled, or lockTimeout elapses.
func waitLock(ctx context.Context, tryLock func() error) error {
	deadline := time.Now().Add(lockTimeout)
	ticker := time.NewTicker(lockPollInterval)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := tryLock(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for output lock: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
