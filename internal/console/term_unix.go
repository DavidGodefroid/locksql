//go:build unix

package console

import (
	"os"
	"os/signal"
	"syscall"
)

// cbreak puts the terminal fd in cbreak mode (no line discipline, no
// echo, one byte at a time) and returns the function that restores the
// previous mode.
func cbreak(fd int) (func(), error) {
	old, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.IEXTEN
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 1, 0
	if err := setTermios(fd, &raw); err != nil {
		return nil, err
	}
	return func() { _ = setTermios(fd, old) }, nil
}

// notifyResize delivers SIGWINCH on sig until the returned function runs.
func notifyResize(sig chan<- os.Signal) func() {
	signal.Notify(sig, syscall.SIGWINCH)
	return func() { signal.Stop(sig) }
}
