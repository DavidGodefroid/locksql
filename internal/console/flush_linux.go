//go:build linux

package console

import (
	"os"

	"golang.org/x/sys/unix"
)

// flushInput discards the input the terminal received but nobody read
// (tcflush(TCIFLUSH)).
func flushInput(f *os.File) error {
	return unix.IoctlSetInt(int(f.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}

// echoOff turns the terminal echo off, keeping line editing, and returns
// the function that restores the previous state.
func echoOff(f *os.File) (func(), error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }, nil
}
