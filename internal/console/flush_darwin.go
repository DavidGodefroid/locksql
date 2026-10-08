package console

import (
	"os"

	"golang.org/x/sys/unix"
)

// fread is FREAD from <sys/fcntl.h>: TIOCFLUSH with it flushes the input
// queue only, like tcflush(TCIFLUSH).
const fread = 1

// flushInput discards the input the terminal received but nobody read.
func flushInput(f *os.File) error {
	return unix.IoctlSetPointerInt(int(f.Fd()), unix.TIOCFLUSH, fread)
}

// echoOff turns the terminal echo off, keeping line editing, and returns
// the function that restores the previous state.
func echoOff(f *os.File) (func(), error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TIOCSETA, old) }, nil
}
