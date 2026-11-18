//go:build !windows

package progress

import (
	"os/signal"
	"sync"
	"syscall"
)

var ignoreBrokenPipeOnce sync.Once

func ignoreBrokenPipe() {
	ignoreBrokenPipeOnce.Do(func() {
		signal.Ignore(syscall.SIGPIPE)
	})
}
