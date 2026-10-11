package console

import (
	"errors"
	"os"
)

var errNoTerminal = errors.New("console: terminal control is not supported on Windows: run locksql inside WSL2 (see docs/usage.md, Windows)")

// flushInput refuses on Windows: type-ahead could not be discarded before
// a prompt.
func flushInput(*os.File) error { return errNoTerminal }

// echoOff refuses on Windows.
func echoOff(*os.File) (func(), error) { return nil, errNoTerminal }
