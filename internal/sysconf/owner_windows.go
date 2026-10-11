package sysconf

import (
	"errors"
	"io/fs"
)

// checkRootOwned refuses on Windows: there is no root-owned system file to
// trust, so a separated setup cannot be read there.
func checkRootOwned(path string, _ fs.FileInfo) error {
	if SkipOwnerCheck {
		return nil
	}
	return errors.New("sysconf: " + path + ": the separated setup is not supported on Windows: run locksql inside WSL2 (see docs/usage.md, Windows)")
}
