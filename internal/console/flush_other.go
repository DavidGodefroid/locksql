//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package console

import (
	"errors"
	"os"
)

var errNoTermControl = errors.New("terminal control is not supported on this OS")

// flushInput is not supported here: only the lines the reader already took
// are dropped before a prompt.
func flushInput(*os.File) error { return errNoTermControl }

func echoOff(*os.File) (func(), error) { return nil, errNoTermControl }
